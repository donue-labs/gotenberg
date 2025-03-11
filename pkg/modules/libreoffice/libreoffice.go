package libreoffice

import (
	"fmt"
	"net/http"

	flag "github.com/spf13/pflag"

	"github.com/gotenberg/gotenberg/v8/pkg/gotenberg"
	"github.com/gotenberg/gotenberg/v8/pkg/modules/api"
	libeofficeapi "github.com/gotenberg/gotenberg/v8/pkg/modules/libreoffice/api"
	"github.com/labstack/echo/v4"
)

func init() {
	gotenberg.MustRegisterModule(new(LibreOffice))
}

// LibreOffice is a module which provides a route for converting documents to
// PDF with LibreOffice.
type LibreOffice struct {
	api           libeofficeapi.Uno
	engine        gotenberg.PdfEngine
	disableRoutes bool
}

// Descriptor returns a [LibreOffice]'s module descriptor.
func (mod *LibreOffice) Descriptor() gotenberg.ModuleDescriptor {
	return gotenberg.ModuleDescriptor{
		ID: "libreoffice",
		FlagSet: func() *flag.FlagSet {
			fs := flag.NewFlagSet("libreoffice", flag.ExitOnError)
			fs.Bool("libreoffice-disable-routes", false, "Disable the routes")

			return fs
		}(),
		New: func() gotenberg.Module { return new(LibreOffice) },
	}
}

// Provision sets the module properties.
func (mod *LibreOffice) Provision(ctx *gotenberg.Context) error {
	flags := ctx.ParsedFlags()
	mod.disableRoutes = flags.MustBool("libreoffice-disable-routes")

	provider, err := ctx.Module(new(libeofficeapi.Provider))
	if err != nil {
		return fmt.Errorf("get LibreOffice Uno provider: %w", err)
	}

	libreOfficeApi, err := provider.(libeofficeapi.Provider).LibreOffice()
	if err != nil {
		return fmt.Errorf("get LibreOffice Uno: %w", err)
	}

	mod.api = libreOfficeApi

	provider, err = ctx.Module(new(gotenberg.PdfEngineProvider))
	if err != nil {
		return fmt.Errorf("get PDF engine provider: %w", err)
	}

	engine, err := provider.(gotenberg.PdfEngineProvider).PdfEngine()
	if err != nil {
		return fmt.Errorf("get PDF engine: %w", err)
	}

	mod.engine = engine

	return nil
}

// corsMiddleware creates a middleware function that adds CORS headers to all responses
func corsMiddleware(next echo.HandlerFunc) echo.HandlerFunc {
	return func(c echo.Context) error {
		// Add CORS headers to all responses
		c.Response().Header().Set("Access-Control-Allow-Origin", "*")
		c.Response().Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		c.Response().Header().Set("Access-Control-Allow-Headers", "*")
		c.Response().Header().Set("Access-Control-Allow-Credentials", "true")
		c.Response().Header().Set("Access-Control-Max-Age", "86400")

		// Handle OPTIONS requests
		if c.Request().Method == "OPTIONS" {
			return c.NoContent(http.StatusOK)
		}

		// Continue with the next handler
		return next(c)
	}
}

// Routes returns the HTTP routes.
func (mod *LibreOffice) Routes() ([]api.Route, error) {
	if mod.disableRoutes {
		return nil, nil
	}

	// Create base routes
	routes := []api.Route{
		rootHealthRoute(),
		health1Route(),
		health2Route(),
		uploadRoute(mod.api),
		convertRoute(mod.api, mod.engine),
		// Add catch-all OPTIONS route for any path
		{
			Method: http.MethodOptions,
			Path:   "/*",
			Handler: corsMiddleware(func(c echo.Context) error {
				return c.NoContent(http.StatusOK)
			}),
		},
	}

	// Wrap all existing routes with CORS middleware
	wrappedRoutes := make([]api.Route, len(routes))
	for i, route := range routes {
		originalHandler := route.Handler
		route.Handler = corsMiddleware(originalHandler)
		wrappedRoutes[i] = route
	}

	return wrappedRoutes, nil
}

// Interface guards.
var (
	_ gotenberg.Module      = (*LibreOffice)(nil)
	_ gotenberg.Provisioner = (*LibreOffice)(nil)
	_ api.Router            = (*LibreOffice)(nil)
)
