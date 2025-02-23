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
    db = InitDB()
    defer db.Close()

    loadOAuthConfig()

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

func onlineUsersHandler(w http.ResponseWriter, r *http.Request) {
    // Add cache headers
    w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")
    w.Header().Set("Pragma", "no-cache")
    w.Header().Set("Expires", "0")

    currentUserID := getGoogleID(r)

    // Get chat history users
    chatListUsers := getChatListUsers(currentUserID)

    // Update online status for chat list users
    clients.RLock()
    for i, user := range chatListUsers {
        id, ok := user["id"].(string)
        if ok {
            if _, online := clients.connections[id]; online {
                chatListUsers[i]["online"] = true
            } else {
                chatListUsers[i]["online"] = false
            }
        }
    }
    clients.RUnlock()

    // Get all users from database
    rows, err := db.Query("SELECT google_id, name, picture FROM users")
    if err != nil {
        http.Error(w, "Database error", http.StatusInternalServerError)
        return
    }
    defer rows.Close()

    var allUsers []map[string]string
    for rows.Next() {
        var id, name, picture string
        if err := rows.Scan(&id, &name, &picture); err != nil {
            continue
        }
        allUsers = append(allUsers, map[string]string{
            "id":      id,
            "name":    name,
            "picture": picture,
        })
    }

    // Split into self and others
    var self, others []map[string]string
    clients.RLock()
    for _, user := range allUsers {
        if user["id"] == currentUserID {
            self = append(self, user)
        } else if _, ok := clients.users[user["id"]]; ok {
            others = append(others, user)
        }
    }
    clients.RUnlock()

    templates.ExecuteTemplate(w, "users_list.html", map[string]interface{}{
        "Self":     self,
        "Others":   others,
        "ChatList": chatListUsers,
    })
}

func getChatListUsers(currentUserID string) []map[string]interface{} {
    rows, err := db.Query(`
        SELECT DISTINCT u.google_id as id, u.name, u.picture 
        FROM users u
        JOIN messages m ON u.google_id IN (m.sender_id, m.receiver_id)
        WHERE ? IN (m.sender_id, m.receiver_id)
        AND u.google_id != ?
    `, currentUserID, currentUserID)
    
    if err != nil {
        log.Println("Failed to get chat list users:", err)
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
    })
}

func wsHandler(w http.ResponseWriter, r *http.Request) {
    googleID := getGoogleID(r)
    if googleID == "" {
        http.Error(w, "Unauthorized", http.StatusUnauthorized)
        return
    }

    // Get user info from database
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

    clients.Lock()
    clients.connections[googleID] = conn
    clients.users[googleID] = UserInfo{Name: name, Picture: picture} // Added line to track user info
    clients.Unlock()

    defer func() {
        clients.Lock()
        delete(clients.connections, googleID)
        delete(clients.users, googleID) // Remove user info on disconnect
        clients.Unlock()
        conn.Close()
        broadcastUserListUpdate()
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
            clients.RUnlock()

            // Save message to database
            _, err := db.Exec(
                "INSERT INTO messages (sender_id, receiver_id, content) VALUES (?, ?, ?)",
                googleID, message.To, message.Content,
            )
            if err != nil {
                log.Println("Failed to save message:", err)
            }

            // Send message in real-time if the recipient is online
            clients.RLock()
            if recipientConn, ok := clients.connections[message.To]; ok {
                senderName := clients.users[googleID].Name
                senderPic := clients.users[googleID].Picture
                msgData := map[string]interface{}{
                    "fromId":      googleID,
                    "fromName":    senderName,
                    "fromPicture": senderPic,
                    "content":     message.Content,
                    "timestamp":   time.Now().Format(time.RFC3339),
                }

                if err := recipientConn.WriteJSON(msgData); err != nil {
                    log.Println("Failed to send message:", err)
                }
            }
            clients.RUnlock()
        }
    }
}

func messagesHandler(w http.ResponseWriter, r *http.Request) {
    googleID := getGoogleID(r)
    if googleID == "" {
        http.Error(w, "Unauthorized", http.StatusUnauthorized)
        return
    }

    partnerID := r.URL.Query().Get("with")
    if partnerID == "" {
        http.Error(w, "Missing partner ID", http.StatusBadRequest)
        return
    }

    rows, err := db.Query(`
        SELECT content, timestamp, sender_id FROM messages
        WHERE (sender_id = ? AND receiver_id = ?)
        OR (sender_id = ? AND receiver_id = ?)
        ORDER BY timestamp`,
        googleID, partnerID, partnerID, googleID,
    )
    if err != nil {
        http.Error(w, "Failed to retrieve messages", http.StatusInternalServerError)
        return
    }
    defer rows.Close()

    var messages []Message
    for rows.Next() {
        var msg Message
        if err := rows.Scan(&msg.Content, &msg.Timestamp, &msg.SenderID); err != nil {
            log.Println("Error scanning message:", err)
            continue
        }
        messages = append(messages, msg)
    }

    w.Header().Set("Content-Type", "application/json")
    json.NewEncoder(w).Encode(messages)
}
