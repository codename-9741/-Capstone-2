package handlers

import (
    "net/http"
    "github.com/gin-gonic/gin"
    "nightfall-tsukuyomi/internal/services"
)

type AuthHandler struct {
    authService *services.AuthService
}

func NewAuthHandler(authService *services.AuthService) *AuthHandler {
    return &AuthHandler{
        authService: authService,
    }
}

type RegisterRequest struct {
    Email    string `json:"email" binding:"required,email"`
    Password string `json:"password" binding:"required,min=8"`
    FullName string `json:"full_name" binding:"required"`
}

type LoginRequest struct {
    Email    string `json:"email" binding:"required,email"`
    Password string `json:"password" binding:"required"`
}

type RefreshRequest struct {
    RefreshToken string `json:"refresh_token" binding:"required"`
}

// POST /api/v1/auth/register
func (h *AuthHandler) Register(c *gin.Context) {
    var req RegisterRequest
    if err := c.ShouldBindJSON(&req); err != nil {
        c.JSON(http.StatusBadRequest, gin.H{
            "success": false,
            "error":   err.Error(),
        })
        return
    }
    
    user, err := h.authService.Register(req.Email, req.Password, req.FullName)
    if err != nil {
        c.JSON(http.StatusBadRequest, gin.H{
            "success": false,
            "error":   err.Error(),
        })
        return
    }
    
    c.JSON(http.StatusCreated, gin.H{
        "success": true,
        "data": gin.H{
            "user": gin.H{
                "id":        user.ID,
                "email":     user.Email,
                "full_name": user.FullName,
                "role":      user.Role,
            },
        },
        "message": "User registered successfully. Please login.",
    })
}

// POST /api/v1/auth/login
func (h *AuthHandler) Login(c *gin.Context) {
    var req LoginRequest
    if err := c.ShouldBindJSON(&req); err != nil {
        c.JSON(http.StatusBadRequest, gin.H{
            "success": false,
            "error":   err.Error(),
        })
        return
    }
    
    accessToken, refreshToken, user, err := h.authService.Login(req.Email, req.Password)
    if err != nil {
        c.JSON(http.StatusUnauthorized, gin.H{
            "success": false,
            "error":   err.Error(),
        })
        return
    }
    
    c.JSON(http.StatusOK, gin.H{
        "success": true,
        "data": gin.H{
            "access_token":  accessToken,
            "refresh_token": refreshToken,
            "user": gin.H{
                "id":        user.ID,
                "email":     user.Email,
                "full_name": user.FullName,
                "role":      user.Role,
            },
        },
    })
}

// POST /api/v1/auth/refresh
func (h *AuthHandler) RefreshToken(c *gin.Context) {
    var req RefreshRequest
    if err := c.ShouldBindJSON(&req); err != nil {
        c.JSON(http.StatusBadRequest, gin.H{
            "success": false,
            "error":   err.Error(),
        })
        return
    }
    
    accessToken, err := h.authService.RefreshToken(req.RefreshToken)
    if err != nil {
        c.JSON(http.StatusUnauthorized, gin.H{
            "success": false,
            "error":   err.Error(),
        })
        return
    }
    
    c.JSON(http.StatusOK, gin.H{
        "success": true,
        "data": gin.H{
            "access_token": accessToken,
        },
    })
}

// GET /api/v1/auth/me
func (h *AuthHandler) GetMe(c *gin.Context) {
    userID := c.GetUint("user_id")
    email := c.GetString("email")
    role := c.GetString("role")
    
    c.JSON(http.StatusOK, gin.H{
        "success": true,
        "data": gin.H{
            "user": gin.H{
                "id":    userID,
                "email": email,
                "role":  role,
            },
        },
    })
}
