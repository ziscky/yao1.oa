package main

import (
	"bytes"
	"crypto"
	"crypto/hmac"
	"encoding/base64"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

//No support for additional auth parameters
var OAUTH_VERSION = "1.0"
var SIGNATURE_METHOD_HMAC = "HMAC-"
var CONSUMER_KEY_PARAM = "oauth_consumer_key"
var NONCE_PARAM = "oauth_nonce"
var SIGNATURE_METHOD_PARAM = "oauth_signature_method"
var TIMESTAMP_PARAM = "oauth_timestamp"
var TOKEN_PARAM = "oauth_token"
var HTTP_AUTH_HEADER = "Authorization"
var VERSION_PARAM = "oauth_version"
var SIGNATURE_PARAM = "oauth_signature"
var OAUTH_HEADER = "OAuth "

type Client struct {
	ConsumerKey    string
	ConsumerSecret string
}

//No support for multipart content
func (client *Client) Request(urlString, method, body string, params map[string]string, token *Token) (*http.Response, error) {
	urlObject, err := url.Parse(urlString)
	if err != nil {
		return nil, err
	}

	request := &http.Request{
		Method:        method,
		URL:           urlObject,
		Header:        http.Header{},
		Body:          ioutil.NopCloser(strings.NewReader(body)),
		ContentLength: int64(len(body)),
	}

	vals := url.Values{}
	for k, v := range params {
		vals.Add(k, v)
	}

	request.URL.RawQuery = vals.Encode()
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	var resp *http.Response
	resp, err = makeRequest(client.ConsumerKey, client.ConsumerSecret, token, *request)

	return resp, err
}

func oauthParameters(consumerKey string) *OrderedParams {
	params := NewOrderedParams()
	params.Add(VERSION_PARAM, OAUTH_VERSION)
	params.Add(SIGNATURE_METHOD_PARAM, "HMAC-SHA1")
	params.Add(TIMESTAMP_PARAM, strconv.FormatInt(getUnixTimeSeconds(), 10))
	params.Add(NONCE_PARAM, strconv.FormatInt(generateNonce(), 10))
	params.Add(CONSUMER_KEY_PARAM, consumerKey)
	return params
}

type KeyVal struct {
	Key string
	Val string
}

type KeyVals []KeyVal

//Satisfy sort interface
func (kv KeyVals) Len() int           { return len(kv) }
func (kv KeyVals) Less(i, j int) bool { return kv[i].Key < kv[j].Key }
func (kv KeyVals) Swap(i, j int)      { kv[i], kv[j] = kv[j], kv[i] }

func paramsToSortedPairs(params map[string]string) []KeyVal {
	// Sort parameters alphabetically
	paramPairs := make(KeyVals, len(params))
	i := 0
	for key, value := range params {
		paramPairs[i] = KeyVal{Key: key, Val: value}
		i++
	}
	sort.Sort(paramPairs)

	return paramPairs
}

func parseBody(request *http.Request) (map[string]string, error) {
	userParams := map[string]string{}

	for k, vs := range request.URL.Query() {
		if len(vs) != 1 {
			return nil, fmt.Errorf("Must have exactly one value per param")
		}

		userParams[k] = vs[0]
	}

	return userParams, nil

}

func canonicalizeUrl(u *url.URL) string {
	var buf bytes.Buffer
	buf.WriteString(u.Scheme)
	buf.WriteString("://")
	buf.WriteString(u.Host)
	buf.WriteString(u.Path)

	return buf.String()
}
func HMACSign(message string, tokenSecret, consumerSecret string) (string, error) {
	key := escape(consumerSecret) + "&" + escape(tokenSecret)
	h := hmac.New(crypto.SHA1.New, []byte(key))
	h.Write([]byte(message))
	rawSignature := h.Sum(nil)

	base64signature := base64.StdEncoding.EncodeToString(rawSignature)
	return base64signature, nil
}
func requestString(method string, url string, params *OrderedParams) string {
	result := method + "&" + escape(url)
	for pos, key := range params.Keys() {
		for innerPos, value := range params.Get(key) {
			if pos+innerPos == 0 {
				result += "&"
			} else {
				result += escape("&")
			}
			result += escape(fmt.Sprintf("%s=%s", key, value))
		}
	}
	return result
}

func makeRequest(consumerKey, consumerSecret string, accessToken *Token, request http.Request) (*http.Response, error) {
	serverRequest := &request

	allParams := oauthParameters(consumerKey)
	allParams.Add(TOKEN_PARAM, accessToken.AccessToken)
	authParams := allParams.Clone()

	// TODO(mrjones): put these directly into the paramPairs below?
	userParams, err := parseBody(serverRequest)
	if err != nil {
		return nil, err
	}
	paramPairs := paramsToSortedPairs(userParams)

	for i := range paramPairs {
		allParams.Add(paramPairs[i].Key, paramPairs[i].Val)
	}

	signingURL := serverRequest.URL
	if host := serverRequest.Host; host != "" {
		signingURL.Host = host
	}
	baseString := requestString(serverRequest.Method, canonicalizeUrl(signingURL), allParams)

	signature, err := HMACSign(baseString, accessToken.AccessSecret, consumerSecret)
	if err != nil {
		return nil, err
	}

	authParams.Add(SIGNATURE_PARAM, signature)

	// Set auth header.
	oauthHdr := OAUTH_HEADER
	for pos, key := range authParams.Keys() {
		for innerPos, value := range authParams.Get(key) {
			if pos+innerPos > 0 {
				oauthHdr += ","
			}
			oauthHdr += key + "=\"" + value + "\""
		}
	}

	serverRequest.Header.Add(HTTP_AUTH_HEADER, oauthHdr)

	fmt.Printf("Request: %v\n", serverRequest)

	client := &http.Client{}
	resp, err := client.Do(serverRequest)
	if err != nil {
		return resp, err
	}
	return resp, nil
}

//
type Token struct {
	AccessToken  string
	AccessSecret string
}

func generateNonce() int64 {
	nonce := &Nonce{}
	return nonce.Generate()
}

func getUnixTimeNano() int64 {
	return time.Now().UnixNano()
}
func getUnixTimeSeconds() int64 {
	return time.Now().Unix()
}

type Nonce struct {
	counter int64
	lock    sync.Mutex
}

func (n *Nonce) Generate() int64 {
	n.lock.Lock()
	n.counter++
	r := n.counter
	n.lock.Unlock()
	return r
}

//Simple way to order parameters Mr.Jones
type OrderedParams struct {
	allParams   map[string][]string
	keyOrdering []string
}

func NewOrderedParams() *OrderedParams {
	return &OrderedParams{
		allParams:   make(map[string][]string),
		keyOrdering: make([]string, 0),
	}
}

type ByValue []string

func (a ByValue) Len() int {
	return len(a)
}

func (a ByValue) Swap(i, j int) {
	a[i], a[j] = a[j], a[i]
}

func (a ByValue) Less(i, j int) bool {
	return a[i] < a[j]
}

func (o *OrderedParams) Get(key string) []string {
	sort.Sort(ByValue(o.allParams[key]))
	return o.allParams[key]
}

func (o *OrderedParams) Keys() []string {
	sort.Sort(o)
	return o.keyOrdering
}

func (o *OrderedParams) Add(key, value string) {
	o.AddUnescaped(key, escape(value))
}

func (o *OrderedParams) AddUnescaped(key, value string) {
	if _, exists := o.allParams[key]; !exists {
		o.keyOrdering = append(o.keyOrdering, key)
		o.allParams[key] = make([]string, 1)
		o.allParams[key][0] = value
	} else {
		o.allParams[key] = append(o.allParams[key], value)
	}
}

func (o *OrderedParams) Len() int {
	return len(o.keyOrdering)
}

func (o *OrderedParams) Less(i int, j int) bool {
	return o.keyOrdering[i] < o.keyOrdering[j]
}

func (o *OrderedParams) Swap(i int, j int) {
	o.keyOrdering[i], o.keyOrdering[j] = o.keyOrdering[j], o.keyOrdering[i]
}

func (o *OrderedParams) Clone() *OrderedParams {
	clone := NewOrderedParams()
	for _, key := range o.Keys() {
		for _, value := range o.Get(key) {
			clone.AddUnescaped(key, value)
		}
	}
	return clone
}

//Clever way to generalize escaping of strings
//github.com/mrjones
func escape(s string) string {
	t := make([]byte, 0, 3*len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		if isEscapable(c) {
			t = append(t, '%')
			t = append(t, "0123456789ABCDEF"[c>>4])
			t = append(t, "0123456789ABCDEF"[c&15])
		} else {
			t = append(t, s[i])
		}
	}
	return string(t)
}

func isEscapable(b byte) bool {
	return !('A' <= b && b <= 'Z' || 'a' <= b && b <= 'z' || '0' <= b && b <= '9' || b == '-' || b == '.' || b == '_' || b == '~')

}
