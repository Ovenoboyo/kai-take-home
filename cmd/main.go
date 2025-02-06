package main

import (
	"fmt"
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
		if scanner, err := commands.NewScanArgs(ctx.Request.Body()); err != nil {
			fmt.Println("args parse error", err)
		} else {
			if err := scanner.RunScan(); err != nil {
				fmt.Println("scan error", err)
			}
		}
	case "/query":
	}
}

func main() {
	handler := RequestHandler
	if err := fasthttp.ListenAndServe(":8080", handler); err != nil {
		log.Fatalf("Error in ListenAndServe: %v", err)
	}
}
