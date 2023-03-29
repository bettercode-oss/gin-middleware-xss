package xss

import (
	"bytes"
	"encoding/json"
	"fmt"
	"github.com/gin-gonic/gin"
	"github.com/microcosm-cc/bluemonday"
	"golang.org/x/exp/slices"
	"io/ioutil"
	"log"
	"os"
	"reflect"
	"strings"
)

const (
	ContentType                              = "Content-Type"
	ContentTypeApplicationJson               = "application/json"
	ContentTypeApplicationXWWWFormURLEncoded = "application/x-www-form-urlencoded"
)

type Config struct {
	TargetHttpMethods []string
	UrlsToExclude     []string
}

type xssLogger struct {
	log *log.Logger
}

func newLogger() *xssLogger {
	return &xssLogger{
		log: log.New(os.Stderr, "bettercode-oss/gin-middleware-xss - ", log.LstdFlags),
	}
}

var logger = newLogger()

var readFn = ioutil.ReadAll

func bytesToJson(data []byte) (any, error) {
	var jsonMap any
	if err := json.Unmarshal(data, &jsonMap); err != nil {
		return nil, err
	}
	return jsonMap, nil
}

func jsonToBytes(j any) ([]byte, error) {
	bytesData, err := json.Marshal(j)
	if err != nil {
		return nil, err
	}
	return bytesData, nil
}

func sanitizeField(fieldValue any, p *bluemonday.Policy) any {
	values := reflect.ValueOf(fieldValue)
	switch values.Kind() {
	case reflect.Slice:
		if values.Len() > 0 {
			arr := make([]any, values.Len())
			for i := 0; i < values.Len(); i++ {
				chgField := sanitizeField(values.Index(i).Interface(), p)
				arr[i] = chgField
			}
			return arr
		}
	case reflect.Map:
		obj := make(map[string]any)
		for _, key := range values.MapKeys() {
			chgField := sanitizeField(values.MapIndex(key).Interface(), p)
			obj[key.String()] = chgField
		}
		return obj
	case reflect.String:
		return strings.TrimSpace(p.Sanitize(fmt.Sprintf("%v", fieldValue)))
	case reflect.Bool:
		return fieldValue
	case reflect.Float64:
		return fieldValue
	default:
		return strings.TrimSpace(p.Sanitize(fmt.Sprintf("%v", fieldValue)))
	}
	return nil
}

func Sanitizer(cfg Config) gin.HandlerFunc {
	return func(c *gin.Context) {
		req := c.Request
		contentType := req.Header.Get(ContentType)
		if contentType == ContentTypeApplicationJson && !slices.Contains(cfg.UrlsToExclude, req.RequestURI) &&
			slices.Contains(cfg.TargetHttpMethods, req.Method) && req.Body != nil {
			bodyBytes, err := readFn(req.Body)
			if err != nil {
				logger.log.Println(err)
				c.Next()
				return
			}
			json, err := bytesToJson(bodyBytes)
			if err != nil {
				logger.log.Println(err)
				req.Body = ioutil.NopCloser(bytes.NewBuffer(bodyBytes))
				c.Next()
				return
			}
			result := sanitizeField(json, bluemonday.UGCPolicy())
			jsonBytes, err := jsonToBytes(result)
			if err != nil {
				logger.log.Println(err)
				req.Body = ioutil.NopCloser(bytes.NewBuffer(bodyBytes))
				c.Next()
				return
			}
			req.Body = ioutil.NopCloser(bytes.NewBuffer(jsonBytes))
		}
	}
}
