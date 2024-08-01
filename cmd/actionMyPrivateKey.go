package main

import (
	"fmt"
	"os"

	"github.com/tonyzzp/acme/utils"
)

func actionMyPrivateKey(context *Context) error {
	e := context.Client.InitKey()
	if e != nil {
		fmt.Println("初始化key失败")
		fmt.Println(e)
		return nil
	}
	jwk := context.Client.JWK
	utils.DumpJson(jwk, os.Stdout)
	return nil
}
