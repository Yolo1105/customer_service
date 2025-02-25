package main

import (
    "context"
    "database/sql"
    "encoding/json"
    "fmt"
    "html/template"
    "io"
    "log"
    "net/http"
    "os"
    "runtime"
    "strings"
    "sync"
    "time"

    "github.com/gorilla/sessions"
    "github.com/gorilla/websocket"
    "github.com/joho/godotenv"
    _ "github.com/mattn/go-sqlite3"
    "golang.org/x/oauth2"
    "golang.org/x/oauth2/google"
)

type UserInfo struct {
    Name    string
    Picture string
}

type Message struct {
    ID         int    `json:"id"`
    SenderID   string `json:"sender_id"`
    ReceiverID string `json:"receiver_id"`
    Content    string `json:"content"`
    Timestamp  string `json:"timestamp"`
    Status     string `json:"status"`
    Picture    string `json:"picture,omitempty"`
    Name       string `json:"name,omitempty"`
}

var (
    templates = template.Must(template.ParseGlob("templates/*.html"))

    clients = struct {
        sync.RWMutex
        connections map[string]*websocket.Conn
        users       map[string]UserInfo
    }{
        connections: make(map[string]*websocket.Conn),
        users:       make(map[string]UserInfo),
    }

    upgrader = websocket.Upgrader{
        CheckOrigin:     func(r *http.Request) bool { return true },
        ReadBufferSize:  4096,
        WriteBufferSize: 4096,
    }

    db                *sql.DB
    googleOauthConfig *oauth2.Config
    
    // 添加session存储
    sessionStore = sessions.NewCookieStore([]byte("super-secret-key"))
    
    // 添加服务器启动时间 
    startTime = time.Now()
    debug = os.Getenv("DEBUG") == "true" // 添加调试模式变量
)

func init() {
    // 设置会话选项
    isLocalDev := os.Getenv("ENV") != "production"
    sessionStore.Options = &sessions.Options{
        Path:     "/",
        MaxAge:   3600, // 1小时过期
        HttpOnly: true,
        Secure:   !isLocalDev, // 本地开发时禁用Secure
        SameSite: http.SameSiteLaxMode, // 对Google OAuth更友好
    }
    
    // 设置日志格式
    log.SetFlags(log.Ldate | log.Ltime | log.Lshortfile)
}

func debugLog(format string, args ...interface{}) {
    if debug {
        log.Printf("[DEBUG] "+format, args...)
    }
}

func main() {
    defer func() {
        if r := recover(); r != nil {
            log.Printf("Recovered from panic: %v", r)
        }
    }()

    // 检查模板是否存在
    if _, err := os.Stat("templates/error.html"); os.IsNotExist(err) {
        log.Fatal("Error template not found! Make sure templates/error.html exists")
    }
    
    if _, err := os.Stat("templates/login.html"); os.IsNotExist(err) {
        log.Fatal("Login template not found! Make sure templates/login.html exists")
    }
    
    if _, err := os.Stat("templates/register.html"); os.IsNotExist(err) {
        log.Fatal("Register template not found! Make sure templates/register.html exists")
    }
    
    if _, err := os.Stat("templates/chat.html"); os.IsNotExist(err) {
        log.Fatal("Chat template not found! Make sure templates/chat.html exists")
    }
    
    if _, err := os.Stat("templates/users_list.html"); os.IsNotExist(err) {
        log.Fatal("Users list template not found! Make sure templates/users_list.html exists")
    }

    db = InitDB()
    defer db.Close()

    // 确保数据库连接正常
    if err := db.Ping(); err != nil {
        log.Fatal("Database connection failed:", err)
    }

    loadOAuthConfig()

    // 创建static文件夹
    if _, err := os.Stat("static"); os.IsNotExist(err) {
        os.Mkdir("static", 0755)
    }

    // 静态文件服务
    http.Handle("/static/", http.StripPrefix("/static/", http.FileServer(http.Dir("static"))))

    // 路由设置
    http.HandleFunc("/", indexHandler)
    http.HandleFunc("/login", loginPageHandler)
    http.HandleFunc("/register", registerPageHandler)
    http.HandleFunc("/logout", logoutHandler)
    http.HandleFunc("/chat", chatHandler)
    http.HandleFunc("/ws", wsHandler)
    http.HandleFunc("/messages", messagesHandler)
    http.HandleFunc("/users", onlineUsersHandler)
    http.HandleFunc("/auth/google", googleLoginHandler)
    http.HandleFunc("/auth/google/callback", googleCallbackHandler)
    http.HandleFunc("/register-manual", manualRegisterHandler)

    http.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
        w.Header().Set("Content-Type", "application/json")
        json.NewEncoder(w).Encode(map[string]interface{}{
            "status":        "healthy",
            "connections":   len(clients.connections),
            "uptime":        time.Since(startTime).String(),
            "go_version":    runtime.Version(),
            "go_routines":   runtime.NumGoroutine(),
        })
    })   
    
    // 在http处理函数设置区域添加
    http.HandleFunc("/debug/session", func(w http.ResponseWriter, r *http.Request) {
        w.Header().Set("Content-Type", "text/html")
        fmt.Fprintln(w, "<h1>Session & Cookie Debug</h1>")
        
        // 显示所有cookie
        fmt.Fprintln(w, "<h2>Cookies:</h2><ul>")
        for _, cookie := range r.Cookies() {
            fmt.Fprintf(w, "<li>%s = %s (Secure: %v, HttpOnly: %v)</li>", 
                cookie.Name, cookie.Value, cookie.Secure, cookie.HttpOnly)
        }
        fmt.Fprintln(w, "</ul>")
        
        // 显示用户会话
        fmt.Fprintln(w, "<h2>User Session:</h2>")
        session, err := sessionStore.Get(r, "user-session")
        if err != nil {
            fmt.Fprintf(w, "<p>Error getting session: %v</p>", err)
        } else {
            fmt.Fprintln(w, "<ul>")
            for k, v := range session.Values {
                fmt.Fprintf(w, "<li>%v = %v</li>", k, v)
            }
            fmt.Fprintln(w, "</ul>")
        }
        
        // 显示OAuth状态会话
        fmt.Fprintln(w, "<h2>OAuth State Session:</h2>")
        oauthSession, err := sessionStore.Get(r, "oauth-state")
        if err != nil {
            fmt.Fprintf(w, "<p>Error getting OAuth session: %v</p>", err)
        } else {
            fmt.Fprintln(w, "<ul>")
            for k, v := range oauthSession.Values {
                fmt.Fprintf(w, "<li>%v = %v</li>", k, v)
            }
            fmt.Fprintln(w, "</ul>")
        }
        
        // 显示环境状态
        fmt.Fprintln(w, "<h2>Environment:</h2>")
        fmt.Fprintf(w, "<p>Debug Mode: %v</p>", debug)
        fmt.Fprintf(w, "<p>ENV: %s</p>", os.Getenv("ENV"))
        
        // 添加登录链接
        fmt.Fprintln(w, "<p><a href='/login'>Go to Login</a></p>")
        fmt.Fprintln(w, "<p><a href='/logout'>Logout</a></p>")
    })

    // 启动清理任务
    go cleanupSessions()

    fmt.Println("🚀 Server running at http://localhost:8080")
    log.Fatal(http.ListenAndServe(":8080", nil))
}

// 定期清理过期会话和断开连接的用户
func cleanupSessions() {
    ticker := time.NewTicker(30 * time.Minute)
    defer ticker.Stop()
    
    for range ticker.C {
        // 清理数据库中的过期会话
        _, err := db.Exec("DELETE FROM sessions WHERE expires_at < ?", time.Now())
        if err != nil {
            log.Printf("Error cleaning up sessions: %v", err)
        }
        
        // 检查长时间不活跃的连接
        clients.Lock()
        for id := range clients.connections {
            // 尝试从数据库检查用户最后活动时间，忽略错误
            var lastLogin time.Time
            err := db.QueryRow("SELECT COALESCE(last_login, CURRENT_TIMESTAMP) FROM users WHERE google_id = ?", id).Scan(&lastLogin)
            if err == nil && time.Since(lastLogin) > 2*time.Hour {
                // 如果用户超过2小时没有活动，关闭连接
                if conn, ok := clients.connections[id]; ok {
                    conn.Close()
                    delete(clients.connections, id)
                    delete(clients.users, id)
                }
            }
        }
        clients.Unlock()
    }
}

func InitDB() *sql.DB {
    db, err := sql.Open("sqlite3", "users.db")
    if err != nil {
        log.Fatal("Failed to open DB:", err)
    }

    // 设置连接池参数
    db.SetMaxOpenConns(25)
    db.SetMaxIdleConns(5)
    db.SetConnMaxLifetime(5 * time.Minute)

    // 用户表创建
    createTableSQL := `
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        google_id TEXT UNIQUE NOT NULL,
        email TEXT UNIQUE NOT NULL,
        name TEXT NOT NULL,
        picture TEXT,
        registered INTEGER DEFAULT 0
    );
    `
    if _, err := db.Exec(createTableSQL); err != nil {
        log.Fatal("Failed to create users table:", err)
    }

    // 检查是否需要添加 registered 列
    var colCount int
    err = db.QueryRow("SELECT COUNT(*) FROM pragma_table_info('users') WHERE name='registered'").Scan(&colCount)
    if err != nil || colCount == 0 {
        log.Println("Adding 'registered' column to users table...")
        _, err := db.Exec("ALTER TABLE users ADD COLUMN registered INTEGER DEFAULT 0")
        if err != nil {
            log.Printf("Error adding registered column: %v", err)
        }
    }

    // 检查是否需要添加 last_login 列
    err = db.QueryRow("SELECT COUNT(*) FROM pragma_table_info('users') WHERE name='last_login'").Scan(&colCount)
    if err != nil || colCount == 0 {
        log.Println("Adding 'last_login' column to users table...")
        _, err := db.Exec("ALTER TABLE users ADD COLUMN last_login DATETIME")
        if err != nil {
            log.Printf("Error adding last_login column: %v", err)
        }
    }

    // 消息表创建
    createMessagesTable := `
    CREATE TABLE IF NOT EXISTS messages (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        sender_id TEXT NOT NULL,
        receiver_id TEXT NOT NULL,
        content TEXT NOT NULL,
        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
        status TEXT DEFAULT 'sent'
    );
    `
    if _, err := db.Exec(createMessagesTable); err != nil {
        log.Fatal("Failed to create messages table:", err)
    }

    // 添加session表
    createSessionTable := `
    CREATE TABLE IF NOT EXISTS sessions (
        session_id TEXT PRIMARY KEY,
        user_id TEXT NOT NULL,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        expires_at DATETIME,
        FOREIGN KEY(user_id) REFERENCES users(google_id)
    );
    `
    if _, err := db.Exec(createSessionTable); err != nil {
        log.Fatal("Failed to create sessions table:", err)
    }

    fmt.Println("✅ Database initialized successfully!")
    return db
}

func loadOAuthConfig() {
    if err := godotenv.Load(".env"); err != nil {
        log.Println("Could not load .env file, continuing with system environment variables...")
    }    

    clientID := os.Getenv("GOOGLE_CLIENT_ID")
    clientSecret := os.Getenv("GOOGLE_CLIENT_SECRET")
    redirectURL := os.Getenv("GOOGLE_REDIRECT_URL")

    if clientID == "" || clientSecret == "" {
        log.Println("WARNING: Missing Google OAuth credentials!")
    }

    if redirectURL == "" {
        // 本地开发时使用默认redirect URL
        redirectURL = "http://localhost:8080/auth/google/callback"
        log.Println("Using default redirect URL:", redirectURL)
    }

    log.Println("OAuth Config loaded")

    googleOauthConfig = &oauth2.Config{
        ClientID:     clientID,
        ClientSecret: clientSecret,
        RedirectURL:  redirectURL,
        Scopes: []string{
            "https://www.googleapis.com/auth/userinfo.email",
            "https://www.googleapis.com/auth/userinfo.profile",
            "openid",
        },
        Endpoint: google.Endpoint,
    }
}

// 主页处理
func indexHandler(w http.ResponseWriter, r *http.Request) {
    if r.URL.Path != "/" {
        http.NotFound(w, r)
        return
    }
    
    // 检查是否登录
    googleID := getGoogleID(r)
    if googleID != "" {
        // 检查用户是否已注册
        var registered int
        err := db.QueryRow("SELECT COALESCE(registered, 0) FROM users WHERE google_id = ?", googleID).Scan(&registered)
        if err == nil && registered == 1 {
            http.Redirect(w, r, "/chat", http.StatusSeeOther)
            return
        } else {
            http.Redirect(w, r, "/register", http.StatusSeeOther)
            return
        }
    }
    
    http.Redirect(w, r, "/login", http.StatusSeeOther)
}

// 错误处理函数
func renderErrorPage(w http.ResponseWriter, title, message string, code int, returnURL, buttonText string) {
    w.WriteHeader(code)
    templates.ExecuteTemplate(w, "error.html", map[string]interface{}{
        "Title":      title,
        "Message":    message,
        "Code":       code,
        "ReturnURL":  returnURL,
        "ButtonText": buttonText,
    })
}

// 登录页面处理
func loginPageHandler(w http.ResponseWriter, r *http.Request) {
    // 清除任何可能存在的cookie
    http.SetCookie(w, &http.Cookie{
        Name:     "google_id",
        Value:    "",
        Path:     "/",
        MaxAge:   -1,
        HttpOnly: true,
    })
    
    // 清除会话
    session, _ := sessionStore.Get(r, "user-session")
    session.Options.MaxAge = -1
    session.Save(r, w)
    
    // 检查是否已经登录
    googleID := getGoogleID(r)
    if googleID != "" {
        var registered int
        err := db.QueryRow("SELECT COALESCE(registered, 0) FROM users WHERE google_id = ?", googleID).Scan(&registered)
        if err == nil && registered == 1 {
            http.Redirect(w, r, "/chat", http.StatusSeeOther)
            return
        }
    }
    
    // 显示登录页面，可能包含错误消息
    errorMsg := r.URL.Query().Get("error")
    templates.ExecuteTemplate(w, "login.html", map[string]interface{}{
        "Error": errorMsg,
    })
}

// 注册页面处理
func registerPageHandler(w http.ResponseWriter, r *http.Request) {
    googleID := getGoogleID(r)
    if googleID == "" {
        http.Redirect(w, r, "/login", http.StatusSeeOther)
        return
    }

    // 获取用户信息
    var email, name, picture string
    var registered int
    err := db.QueryRow(
        "SELECT email, name, picture, COALESCE(registered, 0) FROM users WHERE google_id = ?", 
        googleID,
    ).Scan(&email, &name, &picture, &registered)
    
    if err != nil {
        log.Printf("Error getting user for registration: %v", err)
        renderErrorPage(w, 
            "User Not Found", 
            "We couldn't find your account. Please try logging in again.",
            http.StatusNotFound,
            "/login",
            "Back to Login",
        )
        return
    }

    // 如果已经注册，直接跳转到聊天
    if registered == 1 {
        http.Redirect(w, r, "/chat", http.StatusSeeOther)
        return
    }

    // 处理注册表单提交
    if r.Method == "POST" {
        r.ParseForm()
        displayName := r.FormValue("display_name")
        if displayName != "" {
            // 更新用户名并标记为已注册
            _, err := db.Exec(
                "UPDATE users SET name = ?, registered = 1, last_login = CURRENT_TIMESTAMP WHERE google_id = ?", 
                displayName, googleID,
            )
            if err != nil {
                log.Println("Error updating user:", err)
                // 检查是否是列不存在的错误，如果是，尝试不更新last_login
                if strings.Contains(err.Error(), "last_login") {
                    _, err = db.Exec(
                        "UPDATE users SET name = ?, registered = 1 WHERE google_id = ?",
                        displayName, googleID,
                    )
                    if err != nil {
                        log.Println("Error updating user (simplified):", err)
                        http.Error(w, "Registration failed", http.StatusInternalServerError)
                        return
                    }
                } else {
                    http.Error(w, "Registration failed", http.StatusInternalServerError)
                    return
                }
            }
            
            // 创建新会话，标记为已登录
            session, _ := sessionStore.Get(r, "user-session")
            session.Values["logged_in"] = true
            session.Save(r, w)

            http.Redirect(w, r, "/chat", http.StatusSeeOther)
            return
        }
    }

    // 显示注册页面
    templates.ExecuteTemplate(w, "register.html", map[string]interface{}{
        "Email": email,
        "Name": name,
        "Picture": picture,
    })
}

func googleLoginHandler(w http.ResponseWriter, r *http.Request) {
    // 创建一个随机状态防止CSRF
    stateToken := fmt.Sprintf("%d", time.Now().UnixNano())
    session, _ := sessionStore.Get(r, "oauth-state")
    session.Values["state"] = stateToken
    
    isLocalDev := os.Getenv("ENV") != "production"
    if isLocalDev {
        session.Options.Secure = false // 本地开发时禁用Secure
    }

    if err := session.Save(r, w); err != nil {
        log.Printf("Failed to save oauth-state session: %v", err)
        // 尝试继续处理
    }

    url := googleOauthConfig.AuthCodeURL(stateToken)
    log.Printf("Redirecting to Google OAuth URL: %s", url)
    http.Redirect(w, r, url, http.StatusTemporaryRedirect)
}

func googleCallbackHandler(w http.ResponseWriter, r *http.Request) {
    log.Println("Starting OAuth callback handling")
    
    // 验证状态以防止CSRF - 适用于本地开发环境
    session, err := sessionStore.Get(r, "oauth-state")
    if err != nil {
        log.Printf("Session error: %v", err)
        http.Redirect(w, r, "/login?error=Session+error", http.StatusSeeOther)
        return
    }
    
    expectedState, ok := session.Values["state"].(string)
    if !ok {
        log.Println("No state found in session")
        // 本地开发时继续处理
        if os.Getenv("ENV") == "production" {
            http.Redirect(w, r, "/login?error=Invalid+state", http.StatusSeeOther)
            return
        }
    }

    receivedState := r.URL.Query().Get("state")
    if receivedState != expectedState && os.Getenv("ENV") == "production" {
        log.Printf("State mismatch: expected %s, got %s", expectedState, receivedState)
        http.Redirect(w, r, "/login?error=State+mismatch", http.StatusSeeOther)
        return
    }

    code := r.URL.Query().Get("code")
    if code == "" {
        log.Println("No auth code received")
        http.Redirect(w, r, "/login?error=No+auth+code", http.StatusSeeOther)
        return
    }

    log.Println("Auth code received, exchanging for token")
    token, err := googleOauthConfig.Exchange(context.Background(), code)
    if err != nil {
        log.Printf("Token exchange failed: %v", err)
        http.Redirect(w, r, "/login?error=Token+exchange+failed", http.StatusSeeOther)
        return
    }

    log.Println("Token exchange successful, fetching user info")
    client := googleOauthConfig.Client(context.Background(), token)
    userInfoResp, err := client.Get("https://www.googleapis.com/oauth2/v3/userinfo")
    if err != nil {
        log.Printf("Failed to get user info: %v", err)
        http.Redirect(w, r, "/login?error=User+info+failed", http.StatusSeeOther)
        return
    }
    defer userInfoResp.Body.Close()

    bodyBytes, _ := io.ReadAll(userInfoResp.Body)
    if debug {
        log.Printf("User info response: %s", string(bodyBytes))
    }
    
    var userInfo map[string]interface{}
    if err := json.Unmarshal(bodyBytes, &userInfo); err != nil {
        log.Printf("Failed to parse user info: %v", err)
        http.Redirect(w, r, "/login?error=Parse+failed", http.StatusSeeOther)
        return
    }

    googleID, _ := userInfo["sub"].(string)
    email, _ := userInfo["email"].(string)
    name, _ := userInfo["name"].(string)
    picture, _ := userInfo["picture"].(string)

    // 保存用户信息到数据库，并检查是否已经注册
    registered := saveUserToDB(googleID, email, name, picture)
    log.Printf("User saved to DB, registered: %v", registered)

    // 设置安全的会话cookie
    isLocalDev := os.Getenv("ENV") != "production"
    http.SetCookie(w, &http.Cookie{
        Name:     "google_id",
        Value:    googleID,
        Path:     "/",
        HttpOnly: true,
        Secure:   !isLocalDev, // 本地环境禁用Secure
        SameSite: http.SameSiteLaxMode,
        MaxAge:   3600, // 1小时
    })

    // 创建用户会话
    userSession, _ := sessionStore.New(r, "user-session")
    userSession.Values["user_id"] = googleID
    
    // 如果已注册，直接进入聊天页面，否则进入注册页面
    if registered {
        log.Println("User is registered, redirecting to chat")
        userSession.Values["logged_in"] = true
        if err := userSession.Save(r, w); err != nil {
            log.Printf("Error saving session: %v", err)
            // 尝试继续即使发生错误
        }
        
        // 更新最后登录时间
        db.Exec("UPDATE users SET last_login = CURRENT_TIMESTAMP WHERE google_id = ?", googleID)
        
        http.Redirect(w, r, "/chat", http.StatusSeeOther)
        return
    } else {
        log.Println("User needs registration, redirecting to register")
        if err := userSession.Save(r, w); err != nil {
            log.Printf("Error saving session: %v", err)
            // 尝试继续即使发生错误
        }
        http.Redirect(w, r, "/register", http.StatusSeeOther)
        return
    }
}

func saveUserToDB(googleID, email, name, picture string) bool {
    // 先检查用户是否已存在
    var registered int
    err := db.QueryRow("SELECT COALESCE(registered, 0) FROM users WHERE google_id = ?", googleID).Scan(&registered)
    
    if err == sql.ErrNoRows {
        // 用户不存在，插入新用户
        _, err = db.Exec(
            "INSERT INTO users (google_id, email, name, picture, registered) VALUES (?, ?, ?, ?, 0)",
            googleID, email, name, picture,
        )
        if err != nil {
            log.Println("❌ Failed to save new user:", err)
        }
        // 尝试更新last_login，忽略可能的错误
        db.Exec("UPDATE users SET last_login = CURRENT_TIMESTAMP WHERE google_id = ?", googleID)

        return false
    } else if err != nil {
        log.Println("❌ Error checking user registration:", err)
        // 如果发生错误，尝试插入用户
        _, err = db.Exec(
            "INSERT OR REPLACE INTO users (google_id, email, name, picture, registered) VALUES (?, ?, ?, ?, 0)",
            googleID, email, name, picture,
        )
        if err != nil {
            log.Println("❌ Failed to save user:", err)
        }
        // 尝试更新last_login，忽略可能的错误
        db.Exec("UPDATE users SET last_login = CURRENT_TIMESTAMP WHERE google_id = ?", googleID)

        return false
    } else {
        // 用户已存在，更新信息
        _, err = db.Exec(
            "UPDATE users SET email = ?, picture = ? WHERE google_id = ?",
            email, picture, googleID,
        )
        if err != nil {
            log.Println("❌ Failed to update user:", err)
        }
        // 尝试更新last_login，忽略可能的错误
        db.Exec("UPDATE users SET last_login = CURRENT_TIMESTAMP WHERE google_id = ?", googleID)

        return registered == 1
    }
}

func broadcastUserListUpdate() {
    clients.RLock()
    defer clients.RUnlock()
    message := []byte("users-update")
    for _, conn := range clients.connections {
        if err := conn.WriteMessage(websocket.TextMessage, message); err != nil {
            continue // 忽略错误，继续发送给其他用户
        }
    }
}

func logoutHandler(w http.ResponseWriter, r *http.Request) {
    googleID := getGoogleID(r)
    if googleID != "" {
        // 关闭WebSocket连接
        clients.Lock()
        if conn, ok := clients.connections[googleID]; ok {
            conn.Close()
        }
        delete(clients.connections, googleID)
        delete(clients.users, googleID)
        clients.Unlock()
        
        // 广播用户列表更新
        broadcastUserListUpdate()
        
        // 删除数据库中的会话
        db.Exec("DELETE FROM sessions WHERE user_id = ?", googleID)
        
        // 清除会话
        session, _ := sessionStore.Get(r, "user-session")
        session.Options.MaxAge = -1
        session.Save(r, w)
    }
    
    // 清除cookie
    http.SetCookie(w, &http.Cookie{
        Name:     "google_id",
        Value:    "",
        Path:     "/",
        MaxAge:   -1,
        HttpOnly: true,
    })
    
    http.Redirect(w, r, "/login", http.StatusSeeOther)
}

func getPastChatUsers(currentUserID string) []map[string]interface{} {
    rows, err := db.Query(`
        SELECT DISTINCT u.google_id, u.name, u.picture 
        FROM users u
        JOIN messages m ON u.google_id = m.sender_id OR u.google_id = m.receiver_id
        WHERE (m.sender_id = ? OR m.receiver_id = ?)
        AND u.google_id != ?
        GROUP BY u.google_id
    `, currentUserID, currentUserID, currentUserID)

    if err != nil {
        log.Println("Failed to get past chat users:", err)
        return nil
    }
    defer rows.Close()

    var pastChats []map[string]interface{}
    for rows.Next() {
        var id, name, picture string
        if err := rows.Scan(&id, &name, &picture); err == nil {
            pastChats = append(pastChats, map[string]interface{}{
                "id":      id,
                "name":    name,
                "picture": picture,
                "online":  false,
            })
        }
    }
    return pastChats
}

// 优化的用户列表处理函数
func onlineUsersHandler(w http.ResponseWriter, r *http.Request) {
    // 添加缓存控制头
    w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")
    w.Header().Set("Pragma", "no-cache")
    w.Header().Set("Expires", "0")

    currentUserID := getGoogleID(r)
    if currentUserID == "" {
        http.Error(w, "Unauthorized", http.StatusUnauthorized)
        return
    }

    // 检查是否已登录
    session, _ := sessionStore.Get(r, "user-session")
    if auth, ok := session.Values["logged_in"].(bool); !ok || !auth {
        // 强制重新登录
        http.SetCookie(w, &http.Cookie{
            Name:     "google_id",
            Value:    "",
            Path:     "/",
            MaxAge:   -1,
            HttpOnly: true,
        })
        http.Error(w, "Session expired", http.StatusUnauthorized)
        return
    }

    // 尝试更新最后活动时间，忽略可能的错误
    db.Exec("UPDATE users SET last_login = CURRENT_TIMESTAMP WHERE google_id = ?", currentUserID)

    // 获取当前用户信息
    var selfUser struct {
        ID      string
        Name    string
        Picture string
    }
    err := db.QueryRow("SELECT google_id, name, picture FROM users WHERE google_id = ?", currentUserID).Scan(
        &selfUser.ID, &selfUser.Name, &selfUser.Picture,
    )
    if err != nil {
        log.Println("Error getting self user:", err)
        http.Error(w, "User not found", http.StatusInternalServerError)
        return
    }

    // 获取所有其他用户
    rows, err := db.Query(`
        SELECT google_id, name, picture 
        FROM users 
        WHERE google_id != ? AND registered = 1
        ORDER BY name
    `, currentUserID)

    if err != nil {
        log.Println("Error fetching users:", err)
        http.Error(w, "Database error", http.StatusInternalServerError)
        return
    }
    defer rows.Close()

    var allUsers []map[string]interface{}
    
    // 获取在线状态信息
    clients.RLock()
    onlineUsers := make(map[string]bool)
    for id := range clients.connections {
        onlineUsers[id] = true
    }
    clients.RUnlock()
    
    // 获取所有用户
    for rows.Next() {
        var id, name, picture string
        if err := rows.Scan(&id, &name, &picture); err == nil {
            allUsers = append(allUsers, map[string]interface{}{
                "id":      id,
                "name":    name,
                "picture": picture,
                "online":  onlineUsers[id],
            })
        }
    }
    
    templates.ExecuteTemplate(w, "users_list.html", map[string]interface{}{
        "Self": map[string]interface{}{
            "id":      selfUser.ID,
            "name":    selfUser.Name,
            "picture": selfUser.Picture,
            "online":  true,
        },
        "AllUsers": allUsers,
    })
}

func getGoogleID(r *http.Request) string {
    if c, err := r.Cookie("google_id"); err == nil {
        return c.Value
    }
    return ""
}

func getUserName(googleID string) string {
    clients.RLock()
    if user, ok := clients.users[googleID]; ok {
        clients.RUnlock()
        return user.Name
    }
    clients.RUnlock()
    var name string
    err := db.QueryRow("SELECT name FROM users WHERE google_id = ?", googleID).Scan(&name)
    if err != nil {
        log.Println("Failed to get user name:", err)
        return ""
    }
    return name
}

func chatHandler(w http.ResponseWriter, r *http.Request) {
    googleID := getGoogleID(r)
    if googleID == "" {
        http.Redirect(w, r, "/login", http.StatusSeeOther)
        return
    }

    // 验证会话
    session, _ := sessionStore.Get(r, "user-session")
    if auth, ok := session.Values["logged_in"].(bool); !ok || !auth {
        // 清除google_id cookie
        http.SetCookie(w, &http.Cookie{
            Name:     "google_id",
            Value:    "",
            Path:     "/",
            MaxAge:   -1,
            HttpOnly: true,
        })
        http.Redirect(w, r, "/login", http.StatusSeeOther)
        return
    }

    // 检查用户是否已注册
    var registered int
    err := db.QueryRow("SELECT COALESCE(registered, 0) FROM users WHERE google_id = ?", googleID).Scan(&registered)
    if err != nil || registered != 1 {
        http.Redirect(w, r, "/register", http.StatusSeeOther)
        return
    }

    // 获取用户信息
    var name, picture string
    err = db.QueryRow("SELECT name, picture FROM users WHERE google_id = ?", googleID).Scan(&name, &picture)
    if err != nil {
        log.Println("Failed to get user info:", err)
        http.Error(w, "User not found", http.StatusUnauthorized)
        return
    }

    // 尝试更新最后活动时间，忽略可能的错误
    db.Exec("UPDATE users SET last_login = CURRENT_TIMESTAMP WHERE google_id = ?", googleID)

    templates.ExecuteTemplate(w, "chat.html", map[string]interface{}{
        "Username":    name,
        "UserPicture": picture,
        "GoogleID":    googleID,
    })
}

// 优化的WebSocket处理
func wsHandler(w http.ResponseWriter, r *http.Request) {
    googleID := getGoogleID(r)
    if googleID == "" {
        http.Error(w, "Unauthorized", http.StatusUnauthorized)
        return
    }

    // 验证会话
    session, _ := sessionStore.Get(r, "user-session")
    if auth, ok := session.Values["logged_in"].(bool); !ok || !auth {
        http.Error(w, "Session expired", http.StatusUnauthorized)
        return
    }

    // 获取用户信息
    var name, picture string
    err := db.QueryRow("SELECT name, picture FROM users WHERE google_id = ?", googleID).Scan(&name, &picture)
    if err != nil {
        log.Println("Failed to get user info for WS connection:", err)
        http.Error(w, "User not found", http.StatusUnauthorized)
        return
    }

    // 升级HTTP连接为WebSocket
    conn, err := upgrader.Upgrade(w, r, nil)
    if err != nil {
        log.Printf("WebSocket upgrade error: %v", err)
        return
    }
    
    // 设置适当的缓冲区大小
    conn.SetReadLimit(4096) // 限制消息大小
    conn.SetReadDeadline(time.Now().Add(120 * time.Second))

    // 管理连接
    clients.Lock()
    // 关闭可能的旧连接
    if oldConn, exists := clients.connections[googleID]; exists {
        oldConn.Close()
    }
    clients.connections[googleID] = conn
    clients.users[googleID] = UserInfo{Name: name, Picture: picture}
    clients.Unlock()

    // 通知用户列表更新
    broadcastUserListUpdate()

    // 确保在连接关闭时清理资源
    defer func() {
        clients.Lock()
        if clients.connections[googleID] == conn {
            delete(clients.connections, googleID)
            delete(clients.users, googleID)
        }
        clients.Unlock()
        
        conn.Close()
        broadcastUserListUpdate()
    }()

    // WebSocket心跳检测
    go func() {
        ticker := time.NewTicker(30 * time.Second)
        defer ticker.Stop()

        for {
            select {
            case <-ticker.C:
                // 发送ping消息
                if err := conn.WriteControl(websocket.PingMessage, []byte{}, time.Now().Add(10*time.Second)); err != nil {
                    log.Printf("Ping error: %v", err)
                    return
                }
            }
        }
    }()

    // 设置pong处理函数
    conn.SetPongHandler(func(string) error {
        conn.SetReadDeadline(time.Now().Add(120 * time.Second))
        return nil
    })

    // 消息处理循环
    for {
        messageType, data, err := conn.ReadMessage()
        if err != nil {
            if websocket.IsUnexpectedCloseError(err, websocket.CloseGoingAway, websocket.CloseAbnormalClosure) {
                log.Printf("WebSocket error: %v", err)
            }
            break
        }

        if messageType != websocket.TextMessage || len(data) == 0 {
            continue
        }

        // 异步处理消息
        go func(message []byte) {
            if err := handleWebSocketMessage(conn, googleID, message); err != nil {
                log.Printf("Error handling message: %v", err)
            }
        }(data)
    }
}

// 优化消息处理函数
func handleWebSocketMessage(conn *websocket.Conn, senderID string, message []byte) error {
    var msg map[string]interface{}
    if err := json.Unmarshal(message, &msg); err != nil {
        return err
    }

    // 检查消息类型
    msgType, _ := msg["type"].(string)

    switch msgType {
    case "typing":
        return handleTypingNotificationFast(conn, senderID, msg)
    case "status_update":
        return handleStatusUpdateFast(conn, senderID, msg)
    default:
        // 默认处理聊天消息
        return handleChatMessageFast(conn, senderID, msg)
    }
}

// 高效处理聊天消息
func handleChatMessageFast(conn *websocket.Conn, senderID string, msg map[string]interface{}) error {
    receiverID, ok := msg["to"].(string)
    if !ok || receiverID == "" {
        return fmt.Errorf("invalid receiver ID")
    }
    
    content, ok := msg["content"].(string)
    if !ok || content == "" {
        return fmt.Errorf("invalid message content")
    }
    
    // 获取发送者信息 - 优先使用缓存
    clients.RLock()
    senderInfo, ok := clients.users[senderID]
    clients.RUnlock()
    
    var senderName, senderPic string
    if ok {
        senderName = senderInfo.Name
        senderPic = senderInfo.Picture
    } else {
        // 回退到数据库查询
        err := db.QueryRow("SELECT name, picture FROM users WHERE google_id = ?", senderID).Scan(&senderName, &senderPic)
        if err != nil {
            log.Println("Error getting sender info:", err)
            return err
        }
    }
    
    // 保存消息到数据库
    var messageID int64
    result, err := db.Exec(
        "INSERT INTO messages (sender_id, receiver_id, content, status) VALUES (?, ?, ?, ?)",
        senderID, receiverID, content, "sent",
    )
    if err != nil {
        log.Println("Error saving message:", err)
        return err
    }
    
    messageID, err = result.LastInsertId()
    if err != nil {
        log.Println("Error getting message ID:", err)
        return err
    }
    
    // 构建响应消息
    responseMsg := map[string]interface{}{
        "id":          messageID,
        "fromId":      senderID,
        "fromName":    senderName,
        "fromPicture": senderPic,
        "content":     content,
        "timestamp":   time.Now().Format(time.RFC3339),
        "status":      "sent",
    }
    
    // 首先回复发送方确认消息已保存
    err = conn.WriteJSON(responseMsg)
    if err != nil {
        log.Printf("Error sending message confirmation: %v", err)
    }
    
    // 检查接收者是否在线
    clients.RLock()
    receiverConn, receiverOnline := clients.connections[receiverID]
    clients.RUnlock()
    
    if receiverOnline {
        // 发送到接收者
        go func() {
            if err := receiverConn.WriteJSON(responseMsg); err != nil {
                log.Println("Error sending message to receiver:", err)
                return
            }
            
            // 更新消息状态为已送达
            db.Exec("UPDATE messages SET status = 'delivered' WHERE id = ?", messageID)
            
            // 通知发送者消息已送达
            deliveredMsg := map[string]interface{}{
                "type":      "status_update",
                "messageId": messageID,
                "fromId":    receiverID,
                "status":    "delivered",
            }
            
            conn.WriteJSON(deliveredMsg)
        }()
    }
    
    return nil
}

// 高效处理输入状态通知
func handleTypingNotificationFast(conn *websocket.Conn, senderID string, msg map[string]interface{}) error {
    receiverID, ok := msg["to"].(string)
    if !ok || receiverID == "" {
        return nil
    }
    
    // 获取发送者名称
    clients.RLock()
    senderInfo, hasInfo := clients.users[senderID]
    receiverConn, receiverOnline := clients.connections[receiverID]
    clients.RUnlock()
    
    if !receiverOnline {
        return nil
    }
    
    var senderName string
    if hasInfo {
        senderName = senderInfo.Name
    } else {
        err := db.QueryRow("SELECT name FROM users WHERE google_id = ?", senderID).Scan(&senderName)
        if err != nil {
            return nil
        }
    }
    
    // 发送通知
    typingMsg := map[string]interface{}{
        "type":     "typing",
        "fromId":   senderID,
        "fromName": senderName,
    }
    
    return receiverConn.WriteJSON(typingMsg)
}

// 高效处理状态更新
func handleStatusUpdateFast(conn *websocket.Conn, senderID string, msg map[string]interface{}) error {
    receiverID, ok := msg["to"].(string)
    if !ok || receiverID == "" {
        return nil
    }
    
    var messageID int64
    
    // 处理不同类型的messageId
    switch id := msg["messageId"].(type) {
    case float64:
        messageID = int64(id)
    case string:
        fmt.Sscanf(id, "%d", &messageID)
    default:
        return nil
    }
    
    status, ok := msg["status"].(string)
    if !ok || (status != "delivered" && status != "read") {
        return nil
    }
    
    // 更新数据库
    _, err := db.Exec(
        "UPDATE messages SET status = ? WHERE id = ? AND sender_id = ?",
        status, messageID, receiverID,
    )
    
    if err != nil {
        log.Printf("Error updating message status: %v", err)
        return nil
    }
    
    // 通知消息发送者
    clients.RLock()
    receiverConn, receiverOnline := clients.connections[receiverID]
    clients.RUnlock()
    
    if receiverOnline {
        statusMsg := map[string]interface{}{
            "type":      "status_update",
            "messageId": messageID,
            "fromId":    senderID,
            "status":    status,
        }
        
        receiverConn.WriteJSON(statusMsg)
    }
    
    return nil
}

// 优化消息历史获取
func messagesHandler(w http.ResponseWriter, r *http.Request) {
    currentUserID := getGoogleID(r)
    if currentUserID == "" {
        http.Error(w, "Unauthorized", http.StatusUnauthorized)
        return
    }

    // 验证会话
    session, _ := sessionStore.Get(r, "user-session")
    if auth, ok := session.Values["logged_in"].(bool); !ok || !auth {
        http.Error(w, "Session expired", http.StatusUnauthorized)
        return
    }

    partnerID := r.URL.Query().Get("with")
    if partnerID == "" {
        http.Error(w, "Missing partner ID", http.StatusBadRequest)
        return
    }
    
    // 限制返回的消息数量
    limit := 100
    
    // 查询消息历史
    rows, err := db.Query(`
        SELECT m.id, m.sender_id, m.content, m.timestamp, m.status, u.name, u.picture 
        FROM messages m
        JOIN users u ON m.sender_id = u.google_id
        WHERE (m.sender_id = ? AND m.receiver_id = ?)
        OR (m.sender_id = ? AND m.receiver_id = ?)
        ORDER BY m.timestamp DESC
        LIMIT ?
    `, currentUserID, partnerID, partnerID, currentUserID, limit,
    )
    
    if err != nil {
        http.Error(w, "Database error: "+err.Error(), http.StatusInternalServerError)
        return
    }
    defer rows.Close()

    var messages []map[string]interface{}
    var messageIDs []int
    
    for rows.Next() {
        var id int
        var senderID, content, timestamp, status, name, picture string
        if err := rows.Scan(&id, &senderID, &content, &timestamp, &status, &name, &picture); err != nil {
            continue
        }
        
        // 如果是接收的未读消息，记录ID以便标记为已读
        if senderID == partnerID && status != "read" {
            messageIDs = append(messageIDs, id)
        }
        
        messages = append(messages, map[string]interface{}{
            "id":         id,
            "sender_id":  senderID,
            "content":    content,
            "timestamp":  timestamp,
            "status":     status,
            "name":       name,
            "picture":    picture,
        })
    }
    
    // 反转列表以按时间顺序显示
    for i, j := 0, len(messages)-1; i < j; i, j = i+1, j-1 {
        messages[i], messages[j] = messages[j], messages[i]
    }
    
    // 在后台更新消息为已读状态
    if len(messageIDs) > 0 {
        go func(ids []int) {
            // 批量更新
            placeholders := make([]string, len(ids))
            for i := range placeholders {
                placeholders[i] = "?"
            }
            
            query := fmt.Sprintf(
                "UPDATE messages SET status = 'read' WHERE id IN (%s)",
                strings.Join(placeholders, ","),
            )
            
            args := make([]interface{}, len(ids))
            for i, id := range ids {
                args[i] = id
            }
            
            _, err := db.Exec(query, args...)
            if err != nil {
                log.Printf("Error updating message status: %v", err)
                return
            }
            
            // 通知发送者消息已读
            clients.RLock()
            if conn, ok := clients.connections[partnerID]; ok {
                for _, id := range ids {
                    readReceipt := map[string]interface{}{
                        "type":      "status_update",
                        "messageId": id,
                        "fromId":    currentUserID,
                        "status":    "read",
                    }
                    conn.WriteJSON(readReceipt)
                }
            }
            clients.RUnlock()
        }(messageIDs)
    }

    w.Header().Set("Content-Type", "application/json")
    json.NewEncoder(w).Encode(messages)
}

// 手动注册处理函数
func manualRegisterHandler(w http.ResponseWriter, r *http.Request) {
    if r.Method == "GET" {
        // 显示注册表单
        w.Header().Set("Content-Type", "text/html")
        fmt.Fprint(w, `
            <!DOCTYPE html>
            <html>
            <head>
                <meta charset="UTF-8">
                <meta name="viewport" content="width=device-width, initial-scale=1.0">
                <title>Manual Registration</title>
                <style>
                    body {
                        font-family: "Segoe UI", Tahoma, Geneva, Verdana, sans-serif;
                        background-color: #f9f9f9;
                        display: flex;
                        justify-content: center;
                        align-items: center;
                        height: 100vh;
                        margin: 0;
                        padding: 0;
                    }
                    .container {
                        background-color: white;
                        padding: 2rem;
                        border-radius: 8px;
                        box-shadow: 0 0 20px rgba(0, 0, 0, 0.1);
                        text-align: center;
                        width: 400px;
                    }
                    h1 {
                        color: #4a90e2;
                        margin-bottom: 1.5rem;
                    }
                    form {
                        display: flex;
                        flex-direction: column;
                    }
                    input {
                        padding: 0.75rem;
                        margin-bottom: 1rem;
                        border: 1px solid #ddd;
                        border-radius: 4px;
                    }
                    button {
                        padding: 0.75rem 1.5rem;
                        background-color: #4a90e2;
                        color: white;
                        border: none;
                        border-radius: 4px;
                        font-size: 1rem;
                        font-weight: bold;
                        cursor: pointer;
                        transition: background-color 0.3s ease;
                    }
                    button:hover {
                        background-color: #357ae8;
                    }
                    .login-link {
                        margin-top: 1rem;
                        display: block;
                        color: #4a90e2;
                        text-decoration: none;
                    }
                </style>
            </head>
            <body>
                <div class="container">
                    <h1>Register for Chat</h1>
                    <form method="POST">
                        <input type="text" name="name" placeholder="Your Name" required>
                        <input type="email" name="email" placeholder="Your Email" required>
                        <button type="submit">Register</button>
                    </form>
                    <a href="/login" class="login-link">Already have an account? Login</a>
                </div>
            </body>
            </html>
        `)
        return
    }

    if r.Method == "POST" {
        r.ParseForm()
        name := r.FormValue("name")
        email := r.FormValue("email")
        
        if name == "" || email == "" {
            http.Error(w, "Name and email are required", http.StatusBadRequest)
            return
        }
        
        // 创建一个唯一ID
        googleID := fmt.Sprintf("manual_%d", time.Now().UnixNano())
        
        // 保存用户到数据库
        _, err := db.Exec(
            "INSERT INTO users (google_id, email, name, picture, registered) VALUES (?, ?, ?, ?, 1)",
            googleID, email, name, "/static/default-avatar.png",
        )
        
        if err != nil {
            log.Printf("Error creating manual user: %v", err)
            http.Error(w, "Registration failed. Please try again.", http.StatusInternalServerError)
            return
        }
        
        // 尝试更新last_login，忽略可能的错误
        db.Exec("UPDATE users SET last_login = CURRENT_TIMESTAMP WHERE google_id = ?", googleID)
        
        // 设置cookie和会话
        http.SetCookie(w, &http.Cookie{
            Name:     "google_id",
            Value:    googleID,
            Path:     "/",
            HttpOnly: true,
            MaxAge:   3600,
        })
        
        session, _ := sessionStore.Get(r, "user-session")
        session.Values["user_id"] = googleID
        session.Values["logged_in"] = true
        session.Save(r, w)
        
        // 重定向到聊天页面
        http.Redirect(w, r, "/chat", http.StatusSeeOther)
    }
}
