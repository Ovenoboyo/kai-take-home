package main

import (
	"bytes"
	"log"
	"vuln-scan-api/internal/commands"
	"vuln-scan-api/internal/database"

	"github.com/valyala/fasthttp"
	"github.com/valyala/fasthttp/prefork"
)

// isPostRequest checks if the incoming HTTP request is a POST request.
// Input: ctx - the context of the incoming HTTP request
// Output: returns true if the request method is POST, otherwise false
func isPostRequest(ctx *fasthttp.RequestCtx) bool {
	return string(ctx.Request.Header.Method()) == "POST"
}

// send500 sends a 500 Internal Server Error response.
// Input: ctx - the context of the incoming HTTP request
func send500(ctx *fasthttp.RequestCtx) {
	ctx.Response.SetStatusCode(500)
	ctx.Response.Header.SetStatusMessage([]byte("Internal Server Error"))
}

// send400 sends a 400 Bad Request response.
// Input: ctx - the context of the incoming HTTP request
func send400(ctx *fasthttp.RequestCtx) {
	ctx.Response.SetStatusCode(400)
	ctx.Response.Header.SetStatusMessage([]byte("Bad Request"))
}

// send404 sends a 404 Not Found response.
// Input: ctx - the context of the incoming HTTP request
func send404(ctx *fasthttp.RequestCtx) {
	ctx.Response.SetStatusCode(404)
	ctx.Response.Header.SetStatusMessage([]byte("Not Found"))
}

// send200 sends a 200 OK response.
// Input: ctx - the context of the incoming HTTP request
func send200(ctx *fasthttp.RequestCtx) {
	ctx.Response.SetStatusCode(200)
	ctx.Response.Header.SetStatusMessage([]byte("OK"))
}

// handleGenericRequest processes a generic request by parsing arguments and processing them
// ctx: the context of the incoming HTTP request
// parseArgs: function to parse request body into arguments
// process: function to process the parsed arguments
func handleGenericRequest[T any](ctx *fasthttp.RequestCtx, parseArgs func([]byte) (*T, error), process func(*T) ([]byte, error)) {
	reqBody := ctx.Request.Body()

	args, err := parseArgs(reqBody)
	if err != nil {
		send400(ctx)
		return
	}

	resp, err := process(args)
	if err != nil {
		ctx.SetBody([]byte(err.Error()))
		send500(ctx)
		return
	}

	ctx.SetBody(resp)
	send200(ctx)
}

// handleScan handles the /scan endpoint by processing scan requests
// ctx: the context of the incoming HTTP request
func handleScan(ctx *fasthttp.RequestCtx) {
	handleGenericRequest(ctx, commands.NewScanArgs, (*commands.ScanArgs).RunScan)
}

// handleQuery handles the /query endpoint by processing query requests
// ctx: the context of the incoming HTTP request
func handleQuery(ctx *fasthttp.RequestCtx) {
	handleGenericRequest(ctx, commands.NewQueryArgs, (*commands.QueryArgs).GetVulnsBySeverity)
}

// RequestHandler handles incoming HTTP requests and routes them to the appropriate handler based on the URI path.
// Input: ctx - the context of the incoming HTTP request
func RequestHandler(ctx *fasthttp.RequestCtx) {
	if !isPostRequest(ctx) {
		send404(ctx)
		return
	}

	ctx.Response.Header.Set("Content-Type", "application/json")
	send200(ctx)

	switch path := ctx.Path(); {
	case bytes.Equal(path, []byte("/scan")):
		handleScan(ctx)
	case bytes.Equal(path, []byte("/query")):
		handleQuery(ctx)
	default:
		send404(ctx)
	}

}

// StartServer initializes and starts the HTTP server.
// Output: returns the initialized HTTP server
func StartServer() *fasthttp.Server {
	server := &fasthttp.Server{
		Handler: RequestHandler,
	}

	go func() {
		preforkServer := prefork.New(server)
		if err := preforkServer.ListenAndServe(":8080"); err != nil {
			log.Fatalf("Error in ListenAndServe: %v", err)
		}
	}()

	return server
}

func main() {
	database.Initialize()

	StartServer()

	select {}
}
