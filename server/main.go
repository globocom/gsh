package main

import (
	"os"
	"strconv"

	"github.com/globocom/gsh/server/handlers"
	"github.com/globocom/gsh/server/workers"
	"github.com/globocom/gsh/types"
	"github.com/labstack/echo"
	"github.com/labstack/echo/middleware"
)

func main() {
	// Configuring channels
	var defaultChannelSize, _ = strconv.Atoi(os.Getenv("CHANNEL_SIZE"))
	var auditChannel = make(chan models.AuditRecord, defaultChannelSize)
	var logChannel = make(chan map[string]interface{}, defaultChannelSize)
	var stopChannel = make(chan bool)
	workers.InitWorkers(&auditChannel, &logChannel, &stopChannel)
	defer workers.StopWorkers(&stopChannel)

	// Init echo framework

	e := echo.New()
	// Middlewares
	e.Use(middleware.Logger())

	// Routes (live test if application crash, ready test backend services)
	e.GET("/status/live", handlers.StatusLive)
	e.GET("/status/ready", handlers.StatusReady)
	e.GET("/status/config", handlers.StatusConfig)

	e.Logger.Fatal(e.Start(":" + os.Getenv("PORT")))
}
