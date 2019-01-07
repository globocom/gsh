package main

import (
	"os"

	"github.com/globocom/gsh/ui/config"
	"github.com/globocom/gsh/ui/handlers"
	"github.com/labstack/echo"
	"github.com/labstack/echo/middleware"
)

func main() {
	// Reading configuration
	configuration := config.Init()
	err := config.Check(configuration)
	if err != nil {
		panic(err)
	}

	// Init echo framework
	e := echo.New()

	// Creating handler with pointers to persistent data
	appHandler := handlers.NewAppHandler(configuration)

	// Middlewares
	e.Use(middleware.Logger())

	// Routes (live test if application crash, ready test backend services)
	e.GET("/status/live", handlers.StatusLive)
	e.GET("/status/ready", handlers.StatusReady)
	e.GET("/status/config", appHandler.StatusConfig)

	e.Logger.Fatal(e.Start(":" + os.Getenv("PORT")))
}
