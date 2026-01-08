// Package meteomatics is a client library for the Meteomatics API. See
// https://www.meteomatics.com/en/api/overview/.
package meteomatics

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
)

// DefaultBaseURL is the default base URL.
const DefaultBaseURL = "https://api.meteomatics.com"

type TransportMethod string

const (
	MethodGet  TransportMethod = http.MethodGet
	MethodPost TransportMethod = http.MethodPost
)

// A Client is a Client.
type Client struct {
	httpClient      *http.Client
	baseURL         string
	preRequestFuncs []func(*http.Request)
	method          TransportMethod
}

// A ClientOption sets an option on a Client.
type ClientOption func(*Client)

// RequestOptions are per-request options.
type RequestOptions struct {
	Source                string
	TemporalInterpolation string
	EnsembleSelect        string
	ClusterSelect         string
	Timeout               int
	Route                 bool
}

type TransportOptions struct {
	Method string // http.MethodGet, http.MethodPost
}

// WithBaseURL sets the base URL.
func WithBaseURL(baseURL string) ClientOption {
	return func(c *Client) {
		c.baseURL = baseURL
	}
}

// WithHTTPClient sets the http.Client.
func WithHTTPClient(httpClient *http.Client) ClientOption {
	return func(c *Client) {
		c.httpClient = httpClient
	}
}

// WithBasicAuth sets the username and password for basic authentication.
func WithBasicAuth(username, password string) ClientOption {
	return func(c *Client) {
		c.preRequestFuncs = append(c.preRequestFuncs, func(req *http.Request) {
			req.SetBasicAuth(username, password)
		})
	}
}

// WithBearerAuth adds bearer token header
func WithBearerAuth(token string) ClientOption {
	return func(c *Client) {
		c.preRequestFuncs = append(c.preRequestFuncs, func(req *http.Request) {
			req.Header.Add("Authorization", fmt.Sprintf("bearer %s", token))
		})
	}
}

func WithTransportMethod(method TransportMethod) ClientOption {
	return func(c *Client) {
		c.method = method
	}
}

// NewClient returns a new Client with options set.
func NewClient(options ...ClientOption) *Client {
	c := &Client{
		httpClient: http.DefaultClient,
		baseURL:    DefaultBaseURL,
		method:     MethodGet,
	}
	for _, o := range options {
		o(c)
	}
	return c
}

// Request performs a raw request. It is the caller's responsibility to
// interpret the []byte returned.
func (c *Client) Request(ctx context.Context, ts TimeStringer, ps ParameterStringer, ls LocationStringer, fs FormatStringer, options *RequestOptions) ([]byte, error) {
	var (
		req *http.Request
		err error
	)

	switch c.method {
	case http.MethodPost:
		req, err = c.buildPostRequest(ctx, ts, ps, ls, fs, options)
	default:
		req, err = c.buildGetRequest(ctx, ts, ps, ls, fs, options)
	}
	if err != nil {
		return nil, err
	}

	return c.do(req)
}

func (c *Client) do(req *http.Request) ([]byte, error) {
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	respBody, readErr := io.ReadAll(resp.Body)
	if readErr != nil {
		return nil, readErr
	}

	if resp.StatusCode < http.StatusOK || http.StatusMultipleChoices <= resp.StatusCode {
		return nil, &Error{
			Request:      req,
			Response:     resp,
			ResponseBody: respBody,
		}
	}

	return respBody, nil
}

func (c *Client) buildGetRequest(ctx context.Context, ts TimeStringer, ps ParameterStringer, ls LocationStringer, fs FormatStringer, options *RequestOptions) (*http.Request, error) {
	urlStr := fmt.Sprintf("%s/%s/%s/%s/%s",
		c.baseURL,
		ts.TimeString(),
		ps.ParameterString(),
		ls.LocationString(),
		fs.FormatString(),
	)

	if values := options.Values(); values != nil {
		urlStr += "?" + values.Encode()
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, urlStr, nil)
	if err != nil {
		return nil, err
	}

	c.applyCommonHeaders(req, fs)
	c.applyPreRequest(req)
	return req, nil
}

func (c *Client) buildPostRequest(ctx context.Context, ts TimeStringer, ps ParameterStringer, ls LocationStringer, fs FormatStringer, options *RequestOptions) (*http.Request, error) {
	// URL: /<validdatetime>/
	urlStr := fmt.Sprintf("%s/%s/", c.baseURL, ts.TimeString())

	// Body: <parameters>/<location>/<format>?<optionals>
	bodyStr := fmt.Sprintf("%s/%s/%s", ps.ParameterString(), ls.LocationString(), fs.FormatString())
	if values := options.Values(); values != nil {
		bodyStr += "?" + values.Encode()
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, urlStr, strings.NewReader(bodyStr))
	if err != nil {
		return nil, err
	}

	c.applyCommonHeaders(req, fs)
	req.Header.Set("Content-Type", "text/plain; charset=utf-8")
	c.applyPreRequest(req)
	return req, nil
}

func (c *Client) applyPreRequest(req *http.Request) {
	for _, f := range c.preRequestFuncs {
		f(req)
	}
}

func (c *Client) applyCommonHeaders(req *http.Request, fs FormatStringer) {
	req.Header.Set("Accept", fs.ContentType())
}

// Values returns the url.Values that set the request options defined by o.
func (o *RequestOptions) Values() url.Values {
	if o == nil {
		return nil
	}
	v := url.Values{}
	if o.Source != "" {
		v.Set("source", o.Source)
	}
	if o.TemporalInterpolation != "" {
		v.Set("temporal_interpolation", o.TemporalInterpolation)
	}
	if o.EnsembleSelect != "" {
		v.Set("ens_select", o.EnsembleSelect)
	}
	if o.ClusterSelect != "" {
		v.Set("cluster_select", o.ClusterSelect)
	}
	if o.Timeout != 0 {
		v.Set("timeout", strconv.Itoa(o.Timeout))
	}
	if o.Route {
		v.Set("route", "true")
	}
	if len(v) == 0 {
		return nil
	}
	return v
}
