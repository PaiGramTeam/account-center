package router

// swagger:model healthResponse
type HealthResponse struct {
	// Service health status
	// example: ok
	Status string `json:"status"`
}

// swagger:response healthResponse
type swaggerHealthResponse struct {
	// in: body
	Body HealthResponse
}

// swagger:model rootResponse
type RootResponse struct {
	// Service running message
	// example: Paigram is running
	Message string `json:"message"`
}

// swagger:response rootResponse
type swaggerRootResponse struct {
	// in: body
	Body RootResponse
}
