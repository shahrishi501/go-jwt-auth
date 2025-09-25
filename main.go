package main

import (
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt"
	"github.com/joho/godotenv"
)

var secretKey []byte

func init() {
    godotenv.Load(".env")
	secretKey = []byte(os.Getenv("SECRET_KEY"))
}



type User struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

func main() {

	if len(secretKey) == 0 {
		log.Fatal("SECRET_KEY is not set. Please set it in .env or environment.")
	}

	r := gin.Default()

	r.POST("/login", LoginHandler)
	r.GET("/protected", AuthMiddleware(), ProtectedHandler)

	fmt.Println("🚀 Server running on http://localhost:4000")
	if err := r.Run(":4000"); err != nil {
		fmt.Println("Could not start server:", err)
	}
}

func LoginHandler(c *gin.Context) {
	var user User
	if err := c.ShouldBindJSON(&user); err != nil {
		c.JSON(400, gin.H{"error": "Invalid request"})
		return
	}

	if user.Username == "Chek" && user.Password == "12345678" {
		tokenString, err := createToken(user.Username)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Could not create token"})
			return

		}

		c.JSON(http.StatusOK, gin.H{"token": tokenString})

	}else{
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid credentials"})
	}
}

func ProtectedHandler(c *gin.Context) {
	// If we reach here, the token is valid (checked by middleware)
	username := c.GetString("username")
	c.JSON(http.StatusOK, gin.H{
		"message": fmt.Sprintf("Welcome to the protected area, %s!", username),
	})
}

func AuthMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		authHeader := c.GetHeader("Authorization")
		if len(authHeader) < 8 || authHeader[:7] != "Bearer " {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Missing or invalid Authorization header"})
			return
		}
		tokenString := authHeader[7:]
		claims := jwt.MapClaims{}
		token, err := jwt.ParseWithClaims(tokenString, claims, func(t *jwt.Token) (interface{}, error) {
			return []byte(secretKey), nil
		})
		if err != nil || !token.Valid {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Invalid or expired token"})
			return
		}

		// Save username in context for downstream handlers
		if username, ok := claims["username"].(string); ok {
			c.Set("username", username)
		}
		c.Next()
	}
}

func createToken(username string) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"username": username,
		"exp": time.Now().Add(time.Hour * 24).Unix(),
	})
	return token.SignedString([]byte(secretKey))
}