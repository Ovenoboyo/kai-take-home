package main

import (
	"log"
	"vuln-scan-api/internal/commands"

	"github.com/valyala/fasthttp"
)

func RequestHandler(ctx *fasthttp.RequestCtx) {
	if string(ctx.Request.Header.Method()) != "POST" {
		ctx.Response.SetStatusCode(404)
		return
	}

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
	handler := RequestHandler
	if err := fasthttp.ListenAndServe(":8080", handler); err != nil {
		log.Fatalf("Error in ListenAndServe: %v", err)
	}
}
