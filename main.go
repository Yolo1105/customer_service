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
    "sync"
    "time"

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
    Status     string `json:"status"` // 新增: 消息状态 (sent, delivered, read)
    Picture    string `json:"picture,omitempty"` // 发送者头像
    Name       string `json:"name,omitempty"`    // 发送者名称
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
        CheckOrigin: func(r *http.Request) bool { return true },
        ReadBufferSize:  1024,
        WriteBufferSize: 1024,
    }

    db                *sql.DB
    googleOauthConfig *oauth2.Config
)

func main() {
    db = InitDB()
    defer db.Close()

    loadOAuthConfig()

    // 创建 static 文件夹，如果不存在
    if _, err := os.Stat("static"); os.IsNotExist(err) {
        os.Mkdir("static", 0755)
    }

    // 静态文件服务
    http.Handle("/static/", http.StripPrefix("/static/", http.FileServer(http.Dir("static"))))

    http.HandleFunc("/", loginPageHandler)
    http.HandleFunc("/logout", logoutHandler)
    http.HandleFunc("/chat", chatHandler)
    http.HandleFunc("/ws", wsHandler)
    http.HandleFunc("/messages", messagesHandler)
    http.HandleFunc("/users", onlineUsersHandler)
    http.HandleFunc("/auth/google", googleLoginHandler)
    http.HandleFunc("/auth/google/callback", googleCallbackHandler)

    fmt.Println("🚀 Server running at http://localhost:8080")
    log.Fatal(http.ListenAndServe(":8080", nil))
}

func InitDB() *sql.DB {
    db, err := sql.Open("sqlite3", "users.db")
    if err != nil {
        log.Fatal("Failed to open DB:", err)
    }

    // 用户表创建
    createTableSQL := `
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        google_id TEXT UNIQUE NOT NULL,
        email TEXT UNIQUE NOT NULL,
        name TEXT NOT NULL,
        picture TEXT
    );
    `
    if _, err := db.Exec(createTableSQL); err != nil {
        log.Fatal("Failed to create users table:", err)
    }

    // 消息表创建（添加status字段）
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

    // 尝试添加status列（如果表已存在但没有该列）
    _, err = db.Exec("ALTER TABLE messages ADD COLUMN status TEXT DEFAULT 'sent';")
    // 忽略错误，列可能已存在

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

    log.Println("Loaded OAuth Config:", clientID, redirectURL)

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

func googleLoginHandler(w http.ResponseWriter, r *http.Request) {
    url := googleOauthConfig.AuthCodeURL("randomstate")
    http.Redirect(w, r, url, http.StatusTemporaryRedirect)
}

func googleCallbackHandler(w http.ResponseWriter, r *http.Request) {
    code := r.URL.Query().Get("code")
    if code == "" {
        http.Error(w, "Invalid login request", http.StatusBadRequest)
        return
    }

    token, err := googleOauthConfig.Exchange(context.Background(), code)
    if err != nil {
        log.Println("Failed to exchange token:", err)
        http.Error(w, "Failed to exchange token", http.StatusInternalServerError)
        return
    }

    client := googleOauthConfig.Client(context.Background(), token)
    userInfoResp, err := client.Get("https://www.googleapis.com/oauth2/v3/userinfo")
    if err != nil {
        log.Println("Failed to get user info:", err)
        http.Error(w, "Failed to get user info", http.StatusInternalServerError)
        return
    }
    defer userInfoResp.Body.Close()

    bodyBytes, _ := io.ReadAll(userInfoResp.Body)
    log.Println("Google User Info Response:", string(bodyBytes))

    var userInfo map[string]interface{}
    if err := json.Unmarshal(bodyBytes, &userInfo); err != nil {
        log.Println("Failed to parse user info:", err)
        http.Error(w, "Failed to parse user info", http.StatusInternalServerError)
        return
    }

    googleID, _ := userInfo["sub"].(string)
    email, _ := userInfo["email"].(string)
    name, _ := userInfo["name"].(string)
    picture, _ := userInfo["picture"].(string)

    saveUserToDB(googleID, email, name, picture)

    // Fix session cookie with Secure, SameSite, etc.
    http.SetCookie(w, &http.Cookie{
        Name:     "google_id",
        Value:    googleID,
        Path:     "/",
        HttpOnly: true,
        Secure:   true,
        SameSite: http.SameSiteLaxMode,
        MaxAge:   86400, // 1 day
    })

    http.Redirect(w, r, "/chat", http.StatusSeeOther)
}

func saveUserToDB(googleID, email, name, picture string) {
    _, err := db.Exec(
        "INSERT OR REPLACE INTO users (google_id, email, name, picture) VALUES (?, ?, ?, ?)",
        googleID, email, name, picture,
    )
    if err != nil {
        log.Println("❌ Failed to save user:", err)
    }
}

func broadcastUserListUpdate() {
    clients.RLock()
    defer clients.RUnlock()
    for _, conn := range clients.connections {
        // Notify all connected clients to reload their user list
        if err := conn.WriteMessage(websocket.TextMessage, []byte("users-update")); err != nil {
            log.Println("Failed to broadcast user-list update:", err)
        }
    }
}

func loginPageHandler(w http.ResponseWriter, r *http.Request) {
    googleID := getGoogleID(r)
    username := ""
    if googleID != "" {
        username = getUserName(googleID)
    }
    if username == "" {
        username = "Guest"
    }
    templates.ExecuteTemplate(w, "login.html", map[string]string{
        "Username": username,
    })
}

func logoutHandler(w http.ResponseWriter, r *http.Request) {
    googleID := getGoogleID(r)
    if googleID != "" {
        clients.Lock()
        if conn, ok := clients.connections[googleID]; ok {
            conn.Close()
        }
        delete(clients.connections, googleID)
        delete(clients.users, googleID)
        clients.Unlock()
        broadcastUserListUpdate()
    }
    http.SetCookie(w, &http.Cookie{
        Name:     "google_id",
        Value:    "",
        Path:     "/",
        MaxAge:   -1,
        HttpOnly: true,
    })
    http.Redirect(w, r, "/", http.StatusSeeOther)
}

// Get past chat users
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

// 修改 onlineUsersHandler 函数
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

    // 获取所有用户信息但排除当前用户
    rows, err := db.Query(`
        SELECT google_id, name, picture 
        FROM users 
        WHERE google_id != ?
        ORDER BY name
    `, currentUserID)

    if err != nil {
        log.Println("Error fetching users:", err)
        http.Error(w, "Database error", http.StatusInternalServerError)
        return
    }
    defer rows.Close()

    var allUsers []map[string]interface{}
    
    // 获取所有用户
    for rows.Next() {
        var id, name, picture string
        if err := rows.Scan(&id, &name, &picture); err == nil {
            // 检查在线状态
            clients.RLock()
            _, online := clients.connections[id]
            clients.RUnlock()
            
            allUsers = append(allUsers, map[string]interface{}{
                "id":      id,
                "name":    name,
                "picture": picture,
                "online":  online,
            })
        }
    }
    
    templates.ExecuteTemplate(w, "users_list.html", map[string]interface{}{
        "AllUsers": allUsers,
    })
}

func getChatListUsers(currentUserID string) []map[string]interface{} {
    rows, err := db.Query(`
        SELECT u.google_id as id, u.name, u.picture 
        FROM users u
        WHERE EXISTS (
            SELECT 1 FROM messages m
            WHERE (m.sender_id = ? AND m.receiver_id = u.google_id)
            OR (m.receiver_id = ? AND m.sender_id = u.google_id)
        )
        AND u.google_id != ?
        GROUP BY u.google_id
    `, currentUserID, currentUserID, currentUserID)

    if err != nil {
        log.Println("Error fetching chat list users:", err)
        return nil
    }
    defer rows.Close()

    var chatList []map[string]interface{}
    for rows.Next() {
        var id, name, picture string
        if err := rows.Scan(&id, &name, &picture); err == nil {
            chatList = append(chatList, map[string]interface{}{
                "id":      id,
                "name":    name,
                "picture": picture,
                "online":  false,
            })
        }
    }
    return chatList
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
        http.Redirect(w, r, "/", http.StatusSeeOther)
        return
    }

    var name, picture string
    err := db.QueryRow("SELECT name, picture FROM users WHERE google_id = ?", googleID).Scan(&name, &picture)
    if err != nil {
        log.Println("Failed to get user info:", err)
        http.Error(w, "User not found", http.StatusUnauthorized)
        return
    }

    templates.ExecuteTemplate(w, "chat.html", map[string]interface{}{
        "Username":    name,
        "UserPicture": picture,
        "GoogleID":    googleID,
    })
}

// 优化 WebSocket 消息处理
func wsHandler(w http.ResponseWriter, r *http.Request) {
    googleID := getGoogleID(r)
    if googleID == "" {
        http.Error(w, "Unauthorized", http.StatusUnauthorized)
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

    conn, err := upgrader.Upgrade(w, r, nil)
    if err != nil {
        log.Printf("WebSocket upgrade error: %v", err)
        return
    }

    // 设置较短的写超时以避免长时间阻塞
    conn.SetWriteDeadline(time.Now().Add(5 * time.Second))

    clients.Lock()
    clients.connections[googleID] = conn
    clients.users[googleID] = UserInfo{Name: name, Picture: picture}
    clients.Unlock()

    // 广播用户上线通知（简化以提高性能）
    broadcastUserListUpdate()

    // 确保在连接关闭时清理
    defer func() {
        clients.Lock()
        delete(clients.connections, googleID)
        delete(clients.users, googleID)
        clients.Unlock()
        
        conn.Close()
        broadcastUserListUpdate()
    }()

    // 心跳检测 - 减少频率以降低系统负担
    conn.SetReadDeadline(time.Now().Add(120 * time.Second))
    conn.SetPongHandler(func(string) error {
        conn.SetReadDeadline(time.Now().Add(120 * time.Second))
        return nil
    })

    go func() {
        ticker := time.NewTicker(60 * time.Second)
        defer ticker.Stop()
        for {
            select {
            case <-ticker.C:
                if err := conn.WriteMessage(websocket.PingMessage, nil); err != nil {
                    return
                }
            }
        }
    }()

    // 消息处理循环
    for {
        _, msg, err := conn.ReadMessage()
        if err != nil {
            break
        }

        // 重置写超时
        conn.SetWriteDeadline(time.Now().Add(5 * time.Second))

        go handleWebSocketMessage(conn, googleID, msg) // 使用 goroutine 处理消息以避免阻塞
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
        // 默认处理聊天消息，简化处理流程
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
    
    // 获取发送者信息 - 使用缓存的用户信息而不是数据库查询
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
    
    // 高效发送给接收者
    clients.RLock()
    receiverConn, receiverOnline := clients.connections[receiverID]
    clients.RUnlock()
    
    if receiverOnline {
        // 直接发送到接收者的 WebSocket
        go func() {
            if err := receiverConn.WriteJSON(responseMsg); err != nil {
                log.Println("Error sending message to receiver:", err)
            } else {
                // 更新状态为已送达
                db.Exec("UPDATE messages SET status = 'delivered' WHERE id = ?", messageID)
                
                // 通知发送者消息已送达
                responseMsg["status"] = "delivered"
                conn.WriteJSON(responseMsg)
            }
        }()
    } else {
        // 如果接收者不在线，只需返回发送确认
        conn.WriteJSON(responseMsg)
    }
    
    return nil
}
// 高效处理打字通知
func handleTypingNotificationFast(conn *websocket.Conn, senderID string, msg map[string]interface{}) error {
    receiverID, ok := msg["to"].(string)
    if !ok || receiverID == "" {
        return nil // 直接返回，不报错
    }
    
    // 获取发送者姓名 - 使用缓存的用户信息
    clients.RLock()
    senderInfo, hasInfo := clients.users[senderID]
    receiverConn, receiverOnline := clients.connections[receiverID]
    clients.RUnlock()
    
    if !receiverOnline {
        return nil // 接收者不在线，直接返回
    }
    
    var senderName string
    if hasInfo {
        senderName = senderInfo.Name
    } else {
        // 从数据库获取名字
        db.QueryRow("SELECT name FROM users WHERE google_id = ?", senderID).Scan(&senderName)
    }
    
    // 发送通知到接收者
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
    
    messageID, ok := msg["messageId"].(float64)
    if !ok {
        messageIDStr, isStr := msg["messageId"].(string)
        if !isStr {
            return nil
        }
        fmt.Sscanf(messageIDStr, "%f", &messageID)
    }
    
    status, ok := msg["status"].(string)
    if !ok || (status != "delivered" && status != "read") {
        return nil
    }
    
    // 更新数据库（后台异步）
    go func() {
        db.Exec(
            "UPDATE messages SET status = ? WHERE id = ? AND sender_id = ?",
            status, int64(messageID), receiverID,
        )
    }()
    
    // 通知消息发送者
    clients.RLock()
    receiverConn, receiverOnline := clients.connections[receiverID]
    clients.RUnlock()
    
    if receiverOnline {
        statusMsg := map[string]interface{}{
            "type":      "status_update",
            "messageId": int64(messageID),
            "fromId":    senderID,
            "status":    status,
        }
        
        receiverConn.WriteJSON(statusMsg)
    }
    
    return nil
}

// 优化获取消息历史
func messagesHandler(w http.ResponseWriter, r *http.Request) {
    currentUserID := getGoogleID(r)
    if currentUserID == "" {
        http.Error(w, "Unauthorized", http.StatusUnauthorized)
        return
    }

    partnerID := r.URL.Query().Get("with")
    if partnerID == "" {
        http.Error(w, "Missing partner ID", http.StatusBadRequest)
        return
    }
    
    // 限制返回的消息数量以提高性能
    limit := 100
    
    // 查询消息历史，包含用户信息和状态
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
    var messageIDs []interface{}
    
    for rows.Next() {
        var id int
        var senderID, content, timestamp, status, name, picture string
        if err := rows.Scan(&id, &senderID, &content, &timestamp, &status, &name, &picture); err != nil {
            continue
        }
        
        // 如果是接收的，未读消息，记录ID以便稍后标记为已读
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
        go func() {
            // 构建批量更新的占位符
            placeholders := make([]string, len(messageIDs))
            for i := range placeholders {
                placeholders[i] = "?"
            }
            
            query := fmt.Sprintf(
                "UPDATE messages SET status = 'read' WHERE id IN (%s)",
                strings.Join(placeholders, ","),
            )
            
            // 执行批量更新
            args := make([]interface{}, len(messageIDs))
            for i, id := range messageIDs {
                args[i] = id
            }
            
            db.Exec(query, args...)
            
            // 通知发送者消息已读
            clients.RLock()
            if conn, ok := clients.connections[partnerID]; ok {
                for _, id := range messageIDs {
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
        }()
    }

    w.Header().Set("Content-Type", "application/json")
    json.NewEncoder(w).Encode(messages)
}