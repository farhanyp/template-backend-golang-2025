package main

import (
	"log"
	"os"

	"template-golang-2025/internal/auth"
	"template-golang-2025/internal/example"
	"template-golang-2025/internal/pkg/serverutils"
	token "template-golang-2025/internal/refresh-token"
	user "template-golang-2025/internal/users"
	"template-golang-2025/pkg/database"
	"template-golang-2025/pkg/jwt"

	"github.com/gin-gonic/gin"
	"github.com/joho/godotenv"
)

func main() {
	_ = godotenv.Load()

	// ===== Gin Engine =====
	router := gin.New()

	// Middleware standar Gin
	router.Use(gin.Logger())

	// CORS (simple, bisa kamu ganti gin-contrib/cors)
	router.Use(serverutils.CORSMiddleware())

	// Global error handler (adaptasi dari Fiber)
	router.Use(serverutils.ErrorHandlerMiddlewareGin())

	// ===== Database =====
	db := database.ConnectDB(os.Getenv("DB_CONNECTION_STRING"))

	// ===== Watermill (Pub/Sub) =====

	// ===== JWT =====
	jwtService := jwt.NewJWTService(os.Getenv("JWT-SECRET"), os.Getenv("JWT-ISSUER"))

	// ===== Repository =====
	exampleRepository := example.NewExampleRepository(db)
	userRepository := user.NewUserRepository(db)
	tokenRepository := token.NewUserRepository(db)

	// ===== Service =====
	exampleService := example.NewExampleService(exampleRepository)
	authService := auth.NewAuthService(userRepository, tokenRepository, jwtService, db)

	// ===== Controller =====
	exampleController := example.NewExampleController(exampleService)
	authController := auth.NewAuthController(authService)

	// ===== Routes =====
	api := router.Group("/api")
	{
		exampleController.RegisterRoutes(api)
		authController.RegisterRoutes(api)
	}

	// ===== Start Server =====
	log.Fatal(router.Run(":3000"))
}
