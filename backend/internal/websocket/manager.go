package websocket

import (
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"github.com/gorilla/websocket"
)

// ScanProgress represents scan progress update
type ScanProgress struct {
	ScanID      uint      `json:"scan_id"`
	Status      string    `json:"status"`
	Progress    int       `json:"progress"`
	Message     string    `json:"message"`
	CurrentStep string    `json:"current_step"`
	Timestamp   time.Time `json:"timestamp"`
}

// ScanFinding represents a new finding event
type ScanFinding struct {
	ScanID   uint   `json:"scan_id"`
	Severity string `json:"severity"`
	Category string `json:"category"`
	Finding  string `json:"finding"`
}

// Manager manages WebSocket connections
type Manager struct {
	clients    map[*Client]bool
	broadcast  chan interface{}
	register   chan *Client
	unregister chan *Client
	mu         sync.RWMutex
}

// Client represents a WebSocket client
type Client struct {
	conn   *websocket.Conn
	send   chan interface{}
	scanID uint
}

var manager *Manager

// InitManager initializes the WebSocket manager
func InitManager() *Manager {
	if manager == nil {
		manager = &Manager{
			clients:    make(map[*Client]bool),
			broadcast:  make(chan interface{}),
			register:   make(chan *Client),
			unregister: make(chan *Client),
		}
		go manager.run()
	}
	return manager
}

// GetManager returns the WebSocket manager instance
func GetManager() *Manager {
	if manager == nil {
		return InitManager()
	}
	return manager
}

// run manages client connections
func (m *Manager) run() {
	for {
		select {
		case client := <-m.register:
			m.mu.Lock()
			m.clients[client] = true
			m.mu.Unlock()
			fmt.Printf("[WebSocket] Client connected (total: %d)\n", len(m.clients))

		case client := <-m.unregister:
			m.mu.Lock()
			if _, ok := m.clients[client]; ok {
				delete(m.clients, client)
				close(client.send)
			}
			m.mu.Unlock()
			fmt.Printf("[WebSocket] Client disconnected (total: %d)\n", len(m.clients))

		case message := <-m.broadcast:
			m.mu.RLock()
			for client := range m.clients {
				select {
				case client.send <- message:
				default:
					close(client.send)
					delete(m.clients, client)
				}
			}
			m.mu.RUnlock()
		}
	}
}

// RegisterClient registers a new WebSocket client
func (m *Manager) RegisterClient(conn *websocket.Conn, scanID uint) *Client {
	client := &Client{
		conn:   conn,
		send:   make(chan interface{}, 256),
		scanID: scanID,
	}
	m.register <- client

	// Start read/write pumps
	go client.writePump()
	go client.readPump(m)

	return client
}

// BroadcastProgress sends progress update to all clients
func (m *Manager) BroadcastProgress(scanID uint, progress int, message, step string) {
	m.broadcast <- ScanProgress{
		ScanID:      scanID,
		Status:      "running",
		Progress:    progress,
		Message:     message,
		CurrentStep: step,
		Timestamp:   time.Now(),
	}
}

// BroadcastFinding sends new finding to all clients
func (m *Manager) BroadcastFinding(scanID uint, severity, category, finding string) {
	m.broadcast <- ScanFinding{
		ScanID:   scanID,
		Severity: severity,
		Category: category,
		Finding:  finding,
	}
}

// BroadcastComplete sends scan completion
func (m *Manager) BroadcastComplete(scanID uint, riskScore int, riskGrade string) {
	m.broadcast <- map[string]interface{}{
		"type":       "scan_complete",
		"scan_id":    scanID,
		"risk_score": riskScore,
		"risk_grade": riskGrade,
		"timestamp":  time.Now(),
	}
}

// writePump sends messages to WebSocket client
func (c *Client) writePump() {
	ticker := time.NewTicker(54 * time.Second)
	defer func() {
		ticker.Stop()
		c.conn.Close()
	}()

	for {
		select {
		case message, ok := <-c.send:
			c.conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
			if !ok {
				c.conn.WriteMessage(websocket.CloseMessage, []byte{})
				return
			}

			// Send JSON message
			data, err := json.Marshal(message)
			if err != nil {
				return
			}

			if err := c.conn.WriteMessage(websocket.TextMessage, data); err != nil {
				return
			}

		case <-ticker.C:
			c.conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
			if err := c.conn.WriteMessage(websocket.PingMessage, nil); err != nil {
				return
			}
		}
	}
}

// readPump reads messages from WebSocket client
func (c *Client) readPump(m *Manager) {
	defer func() {
		m.unregister <- c
		c.conn.Close()
	}()

	c.conn.SetReadDeadline(time.Now().Add(60 * time.Second))
	c.conn.SetPongHandler(func(string) error {
		c.conn.SetReadDeadline(time.Now().Add(60 * time.Second))
		return nil
	})

	for {
		_, _, err := c.conn.ReadMessage()
		if err != nil {
			break
		}
	}
}
