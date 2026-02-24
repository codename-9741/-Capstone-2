package middleware

import (
    "net/http"
    "strings"
    "github.com/gin-gonic/gin"
    "github.com/golang-jwt/jwt/v5"
)

func AuthMiddleware(jwtSecret []byte) gin.HandlerFunc {
    return func(c *gin.Context) {
        authHeader := c.GetHeader("Authorization")
        if authHeader == "" {
            c.JSON(http.StatusUnauthorized, gin.H{
                "success": false,
                "error":   "Authorization header required",
            })
            c.Abort()
            return
        }
        
        // Extract token from "Bearer <token>"
        tokenString := strings.TrimPrefix(authHeader, "Bearer ")
        if tokenString == authHeader {
            c.JSON(http.StatusUnauthorized, gin.H{
                "success": false,
                "error":   "Invalid authorization format. Use: Bearer <token>",
            })
            c.Abort()
            return
        }
        
        // Parse and validate token
        token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
            // Verify signing method
            if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
                return nil, jwt.ErrSignatureInvalid
            }
            return jwtSecret, nil
        })
        
        if err != nil || !token.Valid {
            c.JSON(http.StatusUnauthorized, gin.H{
                "success": false,
                "error":   "Invalid or expired token",
            })
            c.Abort()
            return
        }
        
        // Extract claims
        claims, ok := token.Claims.(jwt.MapClaims)
        if !ok {
            c.JSON(http.StatusUnauthorized, gin.H{
                "success": false,
                "error":   "Invalid token claims",
            })
            c.Abort()
            return
        }
        
        // Set user context
        c.Set("user_id", uint(claims["user_id"].(float64)))
        c.Set("email", claims["email"].(string))
        c.Set("role", claims["role"].(string))
        
        c.Next()
    }
}

func RequireRole(allowedRoles ...string) gin.HandlerFunc {
    return func(c *gin.Context) {
        userRole, exists := c.Get("role")
        if !exists {
            c.JSON(http.StatusForbidden, gin.H{
                "success": false,
                "error":   "Role information not found",
            })
            c.Abort()
            return
        }
        
        role := userRole.(string)
        allowed := false
        for _, allowedRole := range allowedRoles {
            if role == allowedRole {
                allowed = true
                break
            }
        }
        
        if !allowed {
            c.JSON(http.StatusForbidden, gin.H{
                "success": false,
                "error":   "Insufficient permissions",
            })
            c.Abort()
            return
        }
        
        c.Next()
    }
}
