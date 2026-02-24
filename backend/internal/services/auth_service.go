package services

import (
    "errors"
    "time"
    "github.com/golang-jwt/jwt/v5"
    "golang.org/x/crypto/bcrypt"
    "gorm.io/gorm"
    "nightfall-tsukuyomi/internal/models"
)

type AuthService struct {
    db        *gorm.DB
    jwtSecret []byte
}

func NewAuthService(db *gorm.DB, jwtSecret string) *AuthService {
    return &AuthService{
        db:        db,
        jwtSecret: []byte(jwtSecret),
    }
}

// Register creates a new user
func (s *AuthService) Register(email, password, fullName string) (*models.User, error) {
    // Check if user already exists
    var existingUser models.User
    if err := s.db.Where("email = ?", email).First(&existingUser).Error; err == nil {
        return nil, errors.New("user already exists")
    }
    
    // Hash password
    hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
    if err != nil {
        return nil, err
    }
    
    // Create user with default organization (ID 1)
    user := &models.User{
        Email:          email,
        PasswordHash:   string(hashedPassword),
        FullName:       fullName,
        Role:           "analyst",
        OrganizationID: nil,
        IsActive:       true,
    }
    
    result := s.db.Create(user)
    if result.Error != nil {
        return nil, result.Error
    }
    
    return user, nil
}

// Login authenticates a user and returns tokens
func (s *AuthService) Login(email, password string) (string, string, *models.User, error) {
    var user models.User
    
    // Find user
    result := s.db.Where("email = ? AND is_active = ?", email, true).First(&user)
    if result.Error != nil {
        return "", "", nil, errors.New("invalid credentials")
    }
    
    // Check password
    err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(password))
    if err != nil {
        return "", "", nil, errors.New("invalid credentials")
    }
    
    // Generate tokens
    accessToken, err := s.generateAccessToken(&user)
    if err != nil {
        return "", "", nil, err
    }
    
    refreshToken, err := s.generateRefreshToken(&user)
    if err != nil {
        return "", "", nil, err
    }
    
    // Update last login
    now := time.Now()
    s.db.Model(&user).Update("last_login", now)
    
    return accessToken, refreshToken, &user, nil
}

func (s *AuthService) generateAccessToken(user *models.User) (string, error) {
    claims := jwt.MapClaims{
        "user_id": user.ID,
        "email":   user.Email,
        "role":    user.Role,
        "exp":     time.Now().Add(24 * time.Hour).Unix(),
        "iat":     time.Now().Unix(),
    }
    
    token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
    return token.SignedString(s.jwtSecret)
}

func (s *AuthService) generateRefreshToken(user *models.User) (string, error) {
    claims := jwt.MapClaims{
        "user_id": user.ID,
        "exp":     time.Now().Add(30 * 24 * time.Hour).Unix(),
        "iat":     time.Now().Unix(),
    }
    
    token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
    return token.SignedString(s.jwtSecret)
}

// RefreshToken generates a new access token from a refresh token
func (s *AuthService) RefreshToken(refreshToken string) (string, error) {
    token, err := jwt.Parse(refreshToken, func(token *jwt.Token) (interface{}, error) {
        return s.jwtSecret, nil
    })
    
    if err != nil || !token.Valid {
        return "", errors.New("invalid refresh token")
    }
    
    claims := token.Claims.(jwt.MapClaims)
    userID := uint(claims["user_id"].(float64))
    
    var user models.User
    if err := s.db.First(&user, userID).Error; err != nil {
        return "", errors.New("user not found")
    }
    
    return s.generateAccessToken(&user)
}
