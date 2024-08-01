package main

import (
	"fmt"
	"os"

	"github.com/tonyzzp/acme/utils"
)

func actionFetchAccount(context *Context) error {
	fmt.Println("通过网络检查账号状态...")
	account := context.Client.GetLocalAccount()
	if account == nil {
		fmt.Println("本地没有账号，请先创建账号")
		return nil
	}
	rtn, e := context.Client.FetchAccount()
	if e != nil {
		fmt.Println("在线获取账号状态失败")
		fmt.Println(e)
		return nil
	}
	utils.DumpJson(rtn, os.Stdout)
	return nil
}
