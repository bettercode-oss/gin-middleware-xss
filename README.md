![Build Status](https://github.com/bettercode-oss/gin-middleware-xss/actions/workflows/build.yml/badge.svg)
[![codecov](https://codecov.io/gh/bettercode-oss/gin-middleware-xss/branch/main/graph/badge.svg?token=tNKcOjlxLo)](https://codecov.io/gh/bettercode-oss/gin-middleware-xss)
![GitHub go.mod Go version](https://img.shields.io/github/go-mod/go-version/bettercode-oss/gin-middleware-xss)
![GitHub release (latest SemVer)](https://img.shields.io/github/v/release/bettercode-oss/gin-middleware-xss)

# [XSS(Cross Site Scripting)](https://owasp.org/www-community/attacks/xss) Gin Middleware
It is a gin middleware that prevents XSS attacks based on [bluemonday](https://github.com/microcosm-cc/bluemonday).

# Usage
## Start using it
Download and install it:
```shell
go get github.com/bettercode-oss/gin-middleware-xss
```
Import it in your code:
```go
import "github.com/bettercode-oss/gin-middleware-xss"
```
## Example
```go
package main

import (
  "github.com/gin-gonic/gin"
  xss "github.com/bettercode-oss/gin-middleware-xss"
  "net/http"
)

func main() {
  r := gin.Default()
  r..Use(xss.Sanitizer(xss.Config{
		TargetHttpMethods: []string{http.MethodPost, http.MethodPut},
		UrlsToExclude:     []string{"/login"},
	}))
  r.Run()
}
```
