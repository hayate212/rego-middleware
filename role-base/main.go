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
	api := e.Group("")
	api.Use(RegoMiddleware())
	api.GET("/", func(c echo.Context) error {
		return c.String(http.StatusOK, "Hello, World!")
	})
	api.GET("/users", func(c echo.Context) error {
		return c.String(http.StatusOK, "get users")
	})
	api.POST("/users", func(c echo.Context) error {
		return c.String(http.StatusOK, "create users")
	})
	e.Start(":8080")
}

func RegoMiddleware() echo.MiddlewareFunc {
	// ポリシー定義を事前にコンパイル
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

			// OPA に渡す入力データを作成
			input := map[string]interface{}{
				"method": c.Request().Method,
				"path":   c.Request().URL.Path,
				"role":   c.Request().Header.Get("role"),
			}
			fmt.Printf("input: %v\n", input)

			// 評価の実行
			results, err := query.Eval(ctx, rego.EvalInput(input))
			if err != nil {
				return c.String(http.StatusInternalServerError, "Internal Server Error")
			}
			// 結果が許可されていない場合は 403 を返す
			if !results.Allowed() {
				return c.String(http.StatusForbidden, "Forbidden")
			}
			return next(c)
		}
	}
}
