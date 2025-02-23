// main.go
package main

import (
    "html/template"
    "log"
    "net/http"
    "sync"
    "encoding/json"

    "github.com/gorilla/websocket"
)

// Message represents a chat message
type Message struct {
    From    string `json:"from"`
    To      string `json:"to"`
    Content string `json:"content"`
}

var (
    templates = template.Must(template.ParseGlob("templates/*.html"))
    
    // Manage active users and their connections
    clients = struct {
        sync.RWMutex
        connections map[string]*websocket.Conn
        users      map[string]bool
    }{
        connections: make(map[string]*websocket.Conn),
        users:      make(map[string]bool),
    }

    upgrader = websocket.Upgrader{
        CheckOrigin: func(r *http.Request) bool { return true },
    }
)

func main() {
    // Routes
    http.HandleFunc("/", loginPageHandler)
    http.HandleFunc("/login", loginHandler)
    http.HandleFunc("/logout", logoutHandler)
    http.HandleFunc("/chat", chatHandler)
    http.HandleFunc("/ws", wsHandler)
    http.HandleFunc("/users", onlineUsersHandler)

    log.Println("Server starting on :8080")
    log.Fatal(http.ListenAndServe(":8080", nil))
}

func loginPageHandler(w http.ResponseWriter, r *http.Request) {
    username := getUsername(r)
    if username == "" {
        username = "Guest" // Default username
    }
    templates.ExecuteTemplate(w, "login.html", map[string]string{
        "Username": username,
    })
}

func loginHandler(w http.ResponseWriter, r *http.Request) {
    username := r.FormValue("username")
    if username == "" {
        http.Error(w, "Username required", http.StatusBadRequest)
        return
    }

    clients.Lock()
    if clients.users[username] {
        clients.Unlock()
        http.Error(w, "Username already taken", http.StatusConflict)
        return
    }
    clients.users[username] = true
    clients.Unlock()

    http.SetCookie(w, &http.Cookie{
        Name:     "username",
        Value:    username,
        Path:     "/",
        HttpOnly: true,
    })
    http.Redirect(w, r, "/chat", http.StatusSeeOther)
}

func logoutHandler(w http.ResponseWriter, r *http.Request) {
    if username := getUsername(r); username != "" {
        clients.Lock()
        delete(clients.users, username)
        if conn := clients.connections[username]; conn != nil {
            conn.Close()
            delete(clients.connections, username)
        }
        clients.Unlock()
    }
    
    http.SetCookie(w, &http.Cookie{
        Name:     "username",
        Value:    "",
        Path:     "/",
        MaxAge:   -1,
        HttpOnly: true,
    })
    http.Redirect(w, r, "/", http.StatusSeeOther)
}

func chatHandler(w http.ResponseWriter, r *http.Request) {
    username := getUsername(r)
    if username == "" {
        http.Redirect(w, r, "/", http.StatusSeeOther)
        return
    }

    clients.RLock()
    users := make([]string, 0, len(clients.users))
    for user := range clients.users {
        if user != username {
            users = append(users, user)
        }
    }
    clients.RUnlock()

    templates.ExecuteTemplate(w, "chat.html", map[string]interface{}{
        "Username": username,
        "Users":    users,
    })
}

func onlineUsersHandler(w http.ResponseWriter, r *http.Request) {
    username := getUsername(r)
    if username == "" {
        http.Error(w, "Unauthorized", http.StatusUnauthorized)
        return
    }

    clients.RLock()
    users := make([]string, 0, len(clients.users))
    for user := range clients.users {
        if user != username {
            users = append(users, user)
        }
    }
    clients.RUnlock()

    templates.ExecuteTemplate(w, "users_list.html", map[string]interface{}{
        "Users": users,
    })
}

func wsHandler(w http.ResponseWriter, r *http.Request) {
    username := getUsername(r)
    if username == "" {
        http.Error(w, "Unauthorized", http.StatusUnauthorized)
        return
    }

    conn, err := upgrader.Upgrade(w, r, nil)
    if err != nil {
        log.Printf("WebSocket upgrade error: %v", err)
        return
    }
    defer conn.Close()

    clients.Lock()
    clients.connections[username] = conn
    clients.Unlock()

    defer func() {
		clients.Lock()
		delete(clients.connections, username)
		delete(clients.users, username)
		clients.Unlock()
	}()

    for {
        _, data, err := conn.ReadMessage()
        if err != nil {
            break
        }

        var msg Message
        if err := json.Unmarshal(data, &msg); err != nil {
            log.Printf("Error unmarshaling message: %v", err)
            continue
        }

        // Send to recipient if online
        clients.RLock()
        if recipientConn := clients.connections[msg.To]; recipientConn != nil {
            msg.From = username
            response, err := json.Marshal(msg)
            if err != nil {
                log.Printf("Error marshaling message: %v", err)
                clients.RUnlock()
                continue
            }
            if err := recipientConn.WriteMessage(websocket.TextMessage, response); err != nil {
                log.Printf("Error sending to %s: %v", msg.To, err)
            }
        }
        clients.RUnlock()
    }
}

func getUsername(r *http.Request) string {
    if c, err := r.Cookie("username"); err == nil {
        return c.Value
    }
    return ""
}