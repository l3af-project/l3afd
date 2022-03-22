package routes

import (
	"github.com/go-chi/chi"
	"time"

	"github.com/go-chi/chi/middleware"
	"github.com/go-chi/cors"
	"github.com/rs/zerolog/log"
)

// NewRouter returns a router handle loaded with all the supported routes
func NewRouter(routes []Route) *chi.Mux {
	r := chi.NewRouter()

	// Add all middlewares here. Timeout one has been added already
	r.Use(middleware.Timeout(5 * time.Minute))

	r.Use(cors.Handler(cors.Options{
		AllowedOrigins: []string{"*"},
		AllowedMethods: []string{"GET", "POST"},
		AllowedHeaders: []string{"Accept", "Authorization", "Content-Type"},
	}))

	for _, route := range routes {
		r.Method(route.Method, route.Path, route.HandlerFunc)
		log.Info().Msgf("Route added:%+v\n", route)
	}

	return r
}
