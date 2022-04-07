// Copyright Contributors to the L3AF Project.
// SPDX-License-Identifier: Apache-2.0

package routes

import (
	chi "github.com/go-chi/chi/v5"
	"github.com/rs/zerolog/log"
)

// NewRouter returns a router handle loaded with all the supported routes
func NewRouter(routes []Route) *chi.Mux {
	r := chi.NewRouter()

	for _, route := range routes {
		r.Method(route.Method, route.Path, route.HandlerFunc)
		log.Info().Msgf("Route added:%+v\n", route)
	}

	return r
}
