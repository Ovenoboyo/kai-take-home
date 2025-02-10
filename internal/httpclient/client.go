package httpclient

import (
	"encoding/json"
	"time"

	"github.com/valyala/fasthttp"
)

type Client[T any] struct {
	client *fasthttp.Client
}

var (
	readTimeout         time.Duration = time.Millisecond * 500
	writeTimeout        time.Duration = time.Millisecond * 500
	maxIdleConnDuration time.Duration = time.Second * 5
)

// NewClient creates a new HTTP client with specified timeouts
// returns: a new instance of Client
func NewClient[T any]() Client[T] {
	client := &fasthttp.Client{
		ReadTimeout:                   readTimeout,
		WriteTimeout:                  writeTimeout,
		MaxIdleConnDuration:           maxIdleConnDuration,
		DisableHeaderNamesNormalizing: true,
		DisablePathNormalizing:        true,
	}
	return Client[T]{
		client: client,
	}
}

// Get sends a GET request to the specified URL and decodes the response
// url: the URL to send the GET request to
// returns: a pointer to the decoded response and an error if the request fails
func (c *Client[T]) Get(url string) (*T, error) {
	req := fasthttp.AcquireRequest()
	req.SetRequestURI(url)
	req.Header.SetMethod(fasthttp.MethodGet)
	resp := fasthttp.AcquireResponse()
	err := c.client.Do(req, resp)
	fasthttp.ReleaseRequest(req)
	defer fasthttp.ReleaseResponse(resp)

	if err != nil {
		return nil, err
	}

	var decoded T
	err = json.Unmarshal(resp.Body(), &decoded)
	if err != nil {
		return nil, err
	}

	return &decoded, nil
}
