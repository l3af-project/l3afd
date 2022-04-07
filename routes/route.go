// Copyright Contributors to the L3AF Project.
// SPDX-License-Identifier: Apache-2.0

package routes

import "net/http"

// Route defines a valid endpoint with the type of action supported on it
type Route struct {
	Method      string
	Path        string
	HandlerFunc http.HandlerFunc
}
