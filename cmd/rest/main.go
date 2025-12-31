package main

import (
	"log"
	"os"

	"template-golang-2025/internal/example"
	"template-golang-2025/internal/pkg/serverutils"
	"template-golang-2025/pkg/database"

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

	// ===== Repository =====
	exampleRepository := example.NewExampleRepository(db)

	// ===== Service =====
	exampleService := example.NewExampleService(exampleRepository)

	// ===== Controller =====
	exampleController := example.NewExampleController(exampleService)

	// ===== Routes =====
	api := router.Group("/api")
	{
		exampleController.RegisterRoutes(api)
	}

	// ===== Start Server =====
	log.Fatal(router.Run(":3000"))
}
