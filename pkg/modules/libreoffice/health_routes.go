package libreoffice

import (
	"net/http"

	"github.com/gotenberg/gotenberg/v8/pkg/modules/api"
	"github.com/labstack/echo/v4"
)

// healthRoute returns the root health check endpoint.
func rootHealthRoute() api.Route {
	return api.Route{
		Method: http.MethodGet,
		Path:   "/",
		Handler: func(c echo.Context) error {
			return c.String(http.StatusOK, "OK")
		},
	}
}

// health1Route returns the health1 endpoint.
func health1Route() api.Route {
	return api.Route{
		Method: http.MethodGet,
		Path:   "/health1",
		Handler: func(c echo.Context) error {
			return c.JSON(http.StatusOK, map[string]int{
				"code": 200,
			})
		},
	}
}

// health2Route returns the health2 endpoint.
func health2Route() api.Route {
	return api.Route{
		Method: http.MethodGet,
		Path:   "/health2",
		Handler: func(c echo.Context) error {
			return c.JSON(http.StatusOK, map[string]int{
				"code": 200,
			})
		},
	}
}
