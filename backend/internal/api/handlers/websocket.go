package handlers

import (
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"
	"github.com/gorilla/websocket"
	wsManager "nightfall-tsukuyomi/internal/websocket"
)

var upgrader = websocket.Upgrader{
	CheckOrigin: func(r *http.Request) bool {
		return true // Allow all origins (configure properly in production)
	},
}

type WebSocketHandler struct {
	manager *wsManager.Manager
}

func NewWebSocketHandler(manager *wsManager.Manager) *WebSocketHandler {
	return &WebSocketHandler{manager: manager}
}

// HandleScanStream handles WebSocket connections for scan updates
func (h *WebSocketHandler) HandleScanStream(c *gin.Context) {
	scanID, err := strconv.ParseUint(c.Param("id"), 10, 32)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid scan ID"})
		return
	}

	// Upgrade HTTP connection to WebSocket
	conn, err := upgrader.Upgrade(c.Writer, c.Request, nil)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to upgrade connection"})
		return
	}

	// Register client
	h.manager.RegisterClient(conn, uint(scanID))
}
