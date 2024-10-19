package routes

import (
	"user-service/internal/handlers"
	"user-service/internal/middleware"

	"github.com/gin-gonic/gin"
)

func SetupRoutes(r *gin.Engine) {
	// Public routes (no RBAC required)
	r.POST("/login", handlers.Login)
	r.POST("/register", handlers.CreateUserHandler)

	// Protected routes (require authentication and role-based access control)
	authGroup := r.Group("/")
	authGroup.Use(middleware.AuthMiddleware()) // Middleware for JWT authentication

	// Role-based access control for routes
	authGroup.GET("/users", middleware.RBACMiddleware("user_read"), handlers.GetAllUsersHandler)

	authGroup.GET("/users/:id", middleware.RBACMiddleware("user_read"), handlers.GetUserByIDHandler)
	authGroup.PUT("/users/:id", middleware.RBACMiddleware("user_update"), handlers.UpdateUser)
}

