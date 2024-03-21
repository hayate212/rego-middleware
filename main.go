package main

import (
	"context"
	"fmt"
	"net/http"

	"github.com/labstack/echo/v4"
	"github.com/open-policy-agent/opa/rego"

	_ "embed"
)

//go:embed policy.rego
var Policy string

func main() {
	e := echo.New()
	api := e.Group("/api")
	api.Use(RegoMiddleware())
	api.GET("/users", func(c echo.Context) error {
		return c.JSON(http.StatusOK, "get users")
	})
	api.POST("/users", func(c echo.Context) error {
		return c.JSON(http.StatusOK, "create users")
	})
	e.Start(":8080")
}

func RegoMiddleware() echo.MiddlewareFunc {
	query, err := rego.New(
		rego.Query("data.app.allow"),
		rego.Module("policy.rego", Policy),
	).PrepareForEval(context.Background())
	if err != nil {
		panic(err)
	}

	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			ctx := c.Request().Context()
			input := map[string]interface{}{
				"method":      c.Request().Method,
				"path":        c.Request().URL.Path,
				"auth":        c.Request().Header.Get("Authorization") != "",
				"permissions": []string{"users:read"},
			}
			fmt.Printf("input: %v\n", input)
			results, err := query.Eval(ctx, rego.EvalInput(input))
			if err != nil {
				return c.String(http.StatusInternalServerError, "Internal Server Error")
			}
			if !results.Allowed() {
				return c.String(http.StatusForbidden, "Forbidden")
			}
			return next(c)
		}
	}
}
