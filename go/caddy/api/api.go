package api

import (
	"context"
	"github.com/inverse-inc/go-utils/log"
	"github.com/inverse-inc/packetfence/go/caddy/caddy"
	"github.com/inverse-inc/packetfence/go/caddy/caddy/caddyhttp/httpserver"
	"github.com/inverse-inc/packetfence/go/db"
	"github.com/inverse-inc/packetfence/go/fbcollectorclient"
	"github.com/inverse-inc/packetfence/go/panichandler"
	"github.com/inverse-inc/packetfence/go/pfconfigdriver"
	"github.com/jinzhu/gorm"
	"github.com/julienschmidt/httprouter"
	"net/http"
	"sync"
	"time"
)

// Register the plugin in caddy
func init() {
	caddy.RegisterPlugin("api", caddy.Plugin{
		ServerType: "http",
		Action:     setup,
	})
}

type APIHandler struct {
	Next   httpserver.Handler
	router *httprouter.Router
}

// Setup the api middleware
// Also loads the pfconfig resources and registers them in the pool
func setup(c *caddy.Controller) error {
	ctx := log.LoggerNewContext(context.Background())

	handler, err := buildHandler(ctx)

	if err != nil {
		return err
	}

	httpserver.GetConfig(c).AddMiddleware(func(next httpserver.Handler) httpserver.Handler {
		handler.Next = next
		return handler
	})

	setupRadiusDictionary()

	pfconfigdriver.PfconfigPool.AddRefreshable(ctx, fbcollectorclient.DefaultClient)

	return nil
}

// Build the Handler which will initialize the routes
func buildHandler(ctx context.Context) (APIHandler, error) {
	apiHandler := APIHandler{}
	router := httprouter.New()

	router.POST("/api/v1/radius_attributes", apiHandler.searchRadiusAttributes)

	router.POST("/api/v1/nodes/fingerbank_communications", apiHandler.nodeFingerbankCommunications)

	var DBP **gorm.DB
	var DB *gorm.DB
	var err error
	done := false
	wait := false

	wg := &sync.WaitGroup{}
	wg.Add(1)

	go func() {
		for {
			if done == false {
				DB, err = gorm.Open("mysql", db.ReturnURIFromConfig(ctx))
				if DB != nil {
					DBP = &DB
					if wait == false {
						wait = true
						wg.Done()
					}
				}

				if DB == nil {
					log.LoggerWContext(ctx).Warn("gorm db is nil while trying to open db")
				}
				if err != nil {
					log.LoggerWContext(ctx).Warn(err.Error())
				}
				if DB != nil && err == nil {
					err := DB.DB().Ping()
					if err == nil {
						done = true
					} else {
						log.LoggerWContext(ctx).Warn(err.Error())
						err := DB.DB().Close()
						if err != nil {
							log.LoggerWContext(ctx).Warn("error occured while closing db: ", err.Error())
						}
					}
				}
				time.Sleep(time.Duration(10) * time.Second)
			} else {
				err := DB.DB().Ping()
				if err != nil {
					done = false
					log.LoggerWContext(ctx).Warn(err.Error())
					err := DB.DB().Close()
					if err != nil {
						log.LoggerWContext(ctx).Warn("error occured while closing db: ", err.Error())
					}
				}
				time.Sleep(time.Duration(5) * time.Second)
			}
		}
	}()

	wg.Wait()
	NewAdminApiAuditLog(ctx, DBP).AddToRouter(router)
	NewAuthLog(ctx, DBP).AddToRouter(router)
	NewDnsAuditLog(ctx, DBP).AddToRouter(router)
	NewRadacctLog(ctx, DBP).AddToRouter(router)
	NewRadiusAuditLog(ctx, DBP).AddToRouter(router)
	NewWrix(ctx, DBP).AddToRouter(router)

	apiHandler.router = router
	return apiHandler, nil
}

func (h APIHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) (int, error) {
	ctx := r.Context()

	defer panichandler.Http(ctx, w)

	if handle, params, _ := h.router.Lookup(r.Method, r.URL.Path); handle != nil {
		// We always default to application/json
		w.Header().Set("Content-Type", "application/json")
		handle(w, r, params)
		return 0, nil
	} else {
		return h.Next.ServeHTTP(w, r)
	}

}
