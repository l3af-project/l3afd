package routes

import "net/http"

// Route defines a valid endpoint with the type of action supported on it
type Route struct {
	Method      string
	Path        string
	HandlerFunc http.HandlerFunc
}
