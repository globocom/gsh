package main

import (
	"context"
	"errors"
	"html/template"
	"io"
	"os"

	oidc "github.com/coreos/go-oidc"
	"github.com/globocom/gsh/ui/config"
	"github.com/globocom/gsh/ui/handlers"
	"github.com/gorilla/sessions"
	"github.com/labstack/echo"
	"github.com/labstack/echo-contrib/session"
	"github.com/labstack/echo/middleware"
	"golang.org/x/oauth2"
)

// TemplateRegistry defines the template registry struct
// Ref: https://medium.freecodecamp.org/how-to-setup-a-nested-html-template-in-the-go-echo-web-framework-670f16244bb4
type TemplateRegistry struct {
	templates map[string]*template.Template
}

// Render implement e.Renderer interface
// Ref: https://medium.freecodecamp.org/how-to-setup-a-nested-html-template-in-the-go-echo-web-framework-670f16244bb4
func (t *TemplateRegistry) Render(w io.Writer, name string, data interface{}, c echo.Context) error {
	tmpl, ok := t.templates[name]
	if !ok {
		err := errors.New("Template not found -> " + name)
		return err
	}
	return tmpl.ExecuteTemplate(w, "base.html", data)
}

func main() {
	// Reading configuration
	configuration := config.Init()
	err := config.Check(configuration)
	if err != nil {
		panic(err)
	}

	// Init echo framework
	e := echo.New()

	// Instantiate a template registry with an array of template set
	// Ref: https://medium.freecodecamp.org/how-to-setup-a-nested-html-template-in-the-go-echo-web-framework-670f16244bb4
	templates := make(map[string]*template.Template)
	templates["request.html"] = template.Must(template.ParseFiles("views/request.html", "views/base.html"))
	e.Renderer = &TemplateRegistry{
		templates: templates,
	}

	// Enable cookie store
	e.Use(session.Middleware(sessions.NewCookieStore([]byte(configuration.GetString("SESSION_STORE_SECRET")))))

	// Configure an OpenID Connect aware OAuth2 client.
	ctx := context.Background()
	oauth2provider, err := oidc.NewProvider(ctx, configuration.GetString("AUTH_REALM_URL"))
	if err != nil {
		panic(err)
	}
	oauth2config := oauth2.Config{
		ClientID:     configuration.GetString("AUTH_RESOURCE"),
		ClientSecret: configuration.GetString("AUTH_CREDENTIALS_SECRET"),
		RedirectURL:  configuration.GetString("AUTH_REDIRECT"),
		Endpoint:     oauth2provider.Endpoint(),
		Scopes:       []string{oidc.ScopeOpenID},
	}

	// Creating handler with pointers to persistent data
	appHandler := handlers.NewAppHandler(configuration, oauth2config, *oauth2provider)

	// Middlewares
	e.Use(middleware.Logger())

	// Routes (live test if application crash, ready test backend services)
	e.GET("/status/live", handlers.StatusLive)
	e.GET("/status/ready", handlers.StatusReady)
	e.GET("/status/config", appHandler.StatusConfig)

	e.GET("/auth", appHandler.Auth)
	e.GET("/auth/callback", appHandler.AuthCallback)
	e.GET("/", appHandler.CertificatePage)

	e.Logger.Fatal(e.Start(":" + os.Getenv("PORT")))
}
