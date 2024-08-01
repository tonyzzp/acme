package main

import (
	"fmt"
	"os"

	"github.com/tonyzzp/acme/utils"
)

func actionMyAccount(context *Context) error {
	account := context.Client.GetLocalAccount()
	if account != nil {
		fmt.Println("本地默认账号")
		utils.DumpJson(account, os.Stdout)
	} else {
		fmt.Println("没有本地账号，开始创建...")
		e := context.Client.InitAccount()
		if e != nil {
			fmt.Println("初始化account失败")
			fmt.Println(e)
			return nil
		}
		utils.DumpJson(context.Client.Account, os.Stdout)
	}
	return nil
}
