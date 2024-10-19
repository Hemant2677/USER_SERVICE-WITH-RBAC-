package middleware

import (
	"net/http"
	"user-service/internal/database"
	"user-service/pkg/utils"

	"github.com/gin-gonic/gin"
)

func RBACMiddleware(permission string) gin.HandlerFunc {
	return func(c *gin.Context) {
		userID, exists := c.Get("id") // Assuming the userID is set by the AuthMiddleware
		if !exists {
			c.JSON(http.StatusUnauthorized, map[string]any{"error": "User ID not found"})
			c.Abort()
			return
		}

		// Check if the user has the required access using the hasAccess function
		hasPermission := database.HasAccess(userID.(int), permission) 
		if !hasPermission {
			c.JSON(http.StatusForbidden, map[string]any{"error": "Permission denied"})
			c.Abort()
			return
		}

		c.Next()
	}
}
func AuthMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		tokenString := c.GetHeader("Authorization")
		if tokenString == "" {
			c.JSON(http.StatusUnauthorized, map[string]any{"error": "Authorization header missing"})
			c.Abort()
			return
		}

		claims, err := utils.ValidateJWT(tokenString)
		if err != nil {
			c.JSON(http.StatusUnauthorized, map[string]any{"error": "Invalid token"})
			c.Abort()
			return
		}

		// Add the claims to the context
		c.Set("id", claims.ID)
		c.Set("email", claims.Email)
		c.Next()
	}
}
