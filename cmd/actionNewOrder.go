package main

import (
	"fmt"
	"os"

	"github.com/manifoldco/promptui"
	"github.com/tonyzzp/acme"
	"github.com/tonyzzp/acme/utils"
)

func actionNewOrder(context *Context) error {
	p := promptui.Prompt{
		Label: "输入域名",
	}
	domain, e := p.Run()
	if e != nil {
		fmt.Println(e)
		return nil
	}
	account := context.Client.GetLocalAccount()
	if account == nil {
		fmt.Println("没有账号，开始创建")
		e := context.Client.InitAccount()
		if e != nil {
			fmt.Println("创建账号失败")
			fmt.Println(e)
			return nil
		}
	}
	fmt.Println("开始创建order")
	order, e := context.Client.NewOrder([]acme.Identifier{
		{Type: "dns", Value: domain},
	})
	if e != nil {
		fmt.Println("创建order失败")
		fmt.Println(e)
		return nil
	}
	fmt.Println("order:")
	utils.DumpJson(order, os.Stdout)
	return nil
}
