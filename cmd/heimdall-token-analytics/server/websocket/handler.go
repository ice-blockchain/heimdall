// SPDX-License-Identifier: ice License 1.0

package websocket

import (
	"fmt"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
)

type (
	HandlerFunc func(ctx *gin.Context, stream Connection)
)

func Handler(r gin.IRoutes, path string, wsHandler HandlerFunc) {
	r.Any(path, func(c *gin.Context) {
		var wsocket Connection
		var err error

		if c.Request.Header.Get("Upgrade") == "websocket" || (c.Request.Method == http.MethodConnect && c.Request.Proto == "websocket") {
			wsocket, err = Upgrade(c.Writer, c.Request, &Config{
				WriteTimeout: time.Second * 30,
				ReadTimeout:  time.Second * 30,
			})
		}

		switch {
		case err != nil:
			c.AbortWithError(http.StatusBadRequest, fmt.Errorf("websocket upgrade error: %w", err))

		case wsocket != nil:
			wsHandler(c, wsocket)

		default:
			c.AbortWithStatus(http.StatusMethodNotAllowed)
		}
	})
}
