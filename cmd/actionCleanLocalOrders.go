package main

import (
	"fmt"

	"github.com/manifoldco/promptui"
	"github.com/tonyzzp/acme"
	"github.com/tonyzzp/acme/utils"
)

func actionCleanLocalOrders(context *Context) error {
	orders, e := context.Client.GetLocalOrders()
	if e != nil {
		fmt.Println(e)
		return nil
	}
	if len(orders) == 0 {
		fmt.Println("没有订单")
		return nil
	}
	dumpOrders(orders)
	p := promptui.Select{
		Label: "清理本地订单",
		Items: []string{
			"cancel",
			"删除全部",
			"删除invalid",
			"删除valid",
			"选择删除",
		},
	}
	index, _, e := p.Run()
	if e != nil {
		fmt.Println(e)
		return nil
	}
	if index == 0 {
		return nil
	}
	index = index - 1
	if index == 0 {
		e = context.Client.DelLocalOrders()
	} else if index == 1 {
		list := utils.SliceFilter(orders, func(order *acme.Order) bool { return order.Status == "invalid" })
		fmt.Println("将要删除以下订单")
		for _, order := range list {
			fmt.Println(order.ShortDesc())
		}
		for _, order := range list {
			e = context.Client.DelOrder(order)
			fmt.Println("删除", order.Uri, e)
			if e != nil {
				break
			}
		}
	} else if index == 2 {
		list := utils.SliceFilter(orders, func(order *acme.Order) bool { return order.Status == "valid" })
		fmt.Println("将要删除以下订单")
		dumpOrders(list)
		for _, order := range list {
			e = context.Client.DelOrder(order)
			fmt.Println("删除", order.Uri, e)
			if e != nil {
				break
			}
		}
	} else if index == 3 {
		items := []string{"cancel"}
		items = append(items, utils.SliceMap(orders, func(order *acme.Order) string { return order.ShortDesc() })...)
		p = promptui.Select{
			Label: "选择证书",
			Items: items,
		}
		index, _, e = p.Run()
		if e != nil {
			fmt.Println(e)
			return nil
		}
		if index == 0 {
			return nil
		}
		order := orders[index-1]
		fmt.Println("准备删除", order.ShortDesc())
		e = context.Client.DelOrder(order)
	}
	if e != nil {
		fmt.Println(e)
	}
	return nil
}
