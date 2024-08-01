package main

import (
	"fmt"
	"strings"

	"github.com/manifoldco/promptui"
)

func actionDelAccount(context *Context) error {
	account := context.Client.GetLocalAccount()
	if account == nil {
		fmt.Println("没有本地账号")
		return nil
	}
	p := promptui.Prompt{
		Label: "确认删除此账号？ (y/n)",
	}
	ok, e := p.Run()
	if e != nil {
		fmt.Println(e)
		return nil
	}
	if ok == "n" {
		return nil
	}
	if strings.TrimSpace(ok) == "y" {
		e := context.Client.DelAccount()
		if e != nil {
			fmt.Println("删除失败", e)
		} else {
			fmt.Println("删除成功")
		}
	}
	return nil
}
