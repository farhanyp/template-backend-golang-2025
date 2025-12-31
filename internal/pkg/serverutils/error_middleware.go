package serverutils

import (
	"errors"
	"log"
	"net/http"
	"runtime/debug"

	"github.com/gin-gonic/gin"
)

func ErrorHandlerMiddlewareGin() gin.HandlerFunc {
	return func(c *gin.Context) {
		// ===== Panic Recovery =====
		defer func() {
			if r := recover(); r != nil {
				log.Printf("[PANIC RECOVERED] %v\n%s", r, debug.Stack())

				c.AbortWithStatusJSON(
					http.StatusInternalServerError,
					ErrorResponse(
						http.StatusInternalServerError,
						"Internal Server Error",
					),
				)
			}
		}()

		// lanjut ke handler
		c.Next()

		// kalau tidak ada error, selesai
		if len(c.Errors) == 0 {
			return
		}

		// ambil error terakhir
		err := c.Errors.Last().Err

		// ===== Custom Errors =====
		if errors.Is(err, ErrNotFound) {
			c.AbortWithStatusJSON(
				http.StatusNotFound,
				ErrorResponse(http.StatusNotFound, "Entity not found"),
			)
			return
		}

		if ve, ok := err.(*ValidationError); ok {
			c.AbortWithStatusJSON(
				http.StatusBadRequest,
				ValidationErrorResponse(ve.ToErrorDetails()),
			)
			return
		}

		// ===== Fallback =====
		log.Printf("[ERROR] %v", err)

		c.AbortWithStatusJSON(
			http.StatusInternalServerError,
			ErrorResponse(http.StatusInternalServerError, err.Error()),
		)
	}
}
