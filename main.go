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
    }

    db                *sql.DB
    googleOauthConfig *oauth2.Config
)

func main() {
    if err := godotenv.Load(".env"); err != nil {
        log.Println("Could not load .env file, continuing with system env vars...")
    }

    db = InitDB()
    defer db.Close()

    loadOAuthConfig()

    http.HandleFunc("/", loginPageHandler)
    http.HandleFunc("/logout", logoutHandler)
    http.HandleFunc("/chat", chatHandler)
    http.HandleFunc("/ws", wsHandler)
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

    fmt.Println("✅ Database initialized successfully!")
    return db
}

func loadOAuthConfig() {
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

func onlineUsersHandler(w http.ResponseWriter, r *http.Request) {
    // Add cache-control headers
    w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")
    w.Header().Set("Pragma", "no-cache")
    w.Header().Set("Expires", "0")

    currentUserID := getGoogleID(r)

    clients.RLock()
    defer clients.RUnlock()

    // Split users into self and others
    var self, others []map[string]string
    for id, user := range clients.users {
        if id == currentUserID {
            self = append(self, map[string]string{
                "id":      id,
                "name":    user.Name,
                "picture": user.Picture,
            })
        } else {
            others = append(others, map[string]string{
                "id":      id,
                "name":    user.Name,
                "picture": user.Picture,
            })
        }
    }

    // Render the partial users_list.html
    templates.ExecuteTemplate(w, "users_list.html", map[string]interface{}{
        "Self":   self,
        "Others": others,
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
    })
}

func wsHandler(w http.ResponseWriter, r *http.Request) {
    googleID := getGoogleID(r)
    if googleID == "" {
        http.Error(w, "Unauthorized", http.StatusUnauthorized)
        return
    }
    var name, picture string
    err := db.QueryRow("SELECT name, picture FROM users WHERE google_id = ?", googleID).Scan(&name, &picture)
    if err != nil {
        log.Println("Failed to get user info:", err)
        http.Error(w, "User not found", http.StatusUnauthorized)
        return
    }

    conn, err := upgrader.Upgrade(w, r, nil)
    if err != nil {
        log.Printf("WebSocket upgrade error: %v", err)
        return
    }

    clients.Lock()
    clients.connections[googleID] = conn
    clients.users[googleID] = UserInfo{Name: name, Picture: picture}
    clients.Unlock()

    broadcastUserListUpdate()

    defer func() {
        clients.Lock()
        delete(clients.connections, googleID)
        delete(clients.users, googleID)
        clients.Unlock()
        broadcastUserListUpdate()
        conn.Close()
    }()

    for {
        _, msg, err := conn.ReadMessage()
        if err != nil {
            log.Println("WebSocket read error:", err)
            break
        }

        var message struct {
            To      string `json:"to"`
            Content string `json:"content"`
        }

        if err := json.Unmarshal(msg, &message); err == nil {
            clients.RLock()
            if message.To == "" {
                log.Println("Received message with empty recipient")
                clients.RUnlock()
                continue
            }
            if recipientConn, ok := clients.connections[message.To]; ok {
                senderName := clients.users[googleID].Name
                senderPic := clients.users[googleID].Picture
                if err := recipientConn.WriteJSON(map[string]string{
                    "fromId":      googleID,
                    "fromName":    senderName,
                    "fromPicture": senderPic,
                    "content":     message.Content,
                }); err != nil {
                    log.Println("Failed to send message:", err)
                }
            }
            clients.RUnlock()
        }
    }
}
