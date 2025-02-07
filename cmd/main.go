package main

import (
	"log"
	"vuln-scan-api/internal/commands"
	"vuln-scan-api/internal/database"

	"github.com/valyala/fasthttp"
	"github.com/valyala/fasthttp/prefork"
)

func RequestHandler(ctx *fasthttp.RequestCtx) {
	if string(ctx.Request.Header.Method()) != "POST" {
		ctx.Response.SetStatusCode(404)
		return
	}

	ctx.Response.Header.Set("Content-Type", "application/json")

	switch string(ctx.Request.URI().Path()) {
	case "/scan":
		if scanner, err := commands.NewScanArgs(ctx.Request.Body()); err == nil {
			if err := scanner.RunScan(); err != nil {
				ctx.Response.SetStatusCode(500)
			}
		} else {
			ctx.Response.SetStatusCode(400)
		}
	case "/query":
		if query, err := commands.NewQueryArgs(ctx.Request.Body()); err == nil {
			if resp, err := query.GetVulnsBySeverity(); err != nil {
				ctx.Response.SetStatusCode(500)
			} else {
				ctx.Response.SetBody(resp)
			}
		} else {
			ctx.Response.SetStatusCode(400)
		}
	}
}

func main() {
	database.Initialize()

	server := &fasthttp.Server{
		Handler: RequestHandler,
	}
	preforkServer := prefork.New(server)
	if err := preforkServer.ListenAndServe(":8080"); err != nil {
		log.Fatalf("Error in ListenAndServe: %v", err)
	}
}
