package main

import (
	"fmt"

	"github.com/tonyzzp/acme"
)

func dumpOrders(orders []*acme.Order) {
	fmt.Println("local orders: ", len(orders))
	for _, order := range orders {
		fmt.Println("-----")
		fmt.Println("  uri: ", order.Uri)
		fmt.Println("  status: ", order.Status)
		fmt.Println("  expires: ", order.Expires)
		fmt.Println("  identifiers: ", order.Identifiers[0])
		fmt.Println("  auth: ", order.Authorizations[0])
		fmt.Println("  finalzie: ", order.Finalize)
		fmt.Println("  certificate: ", order.Certificate)
	}
}

func actionLocalOrders(context *Context) error {
	orders, e := context.Client.GetLocalOrders()
	if e != nil {
		fmt.Println("读取失败")
		fmt.Println(e)
		return nil
	}
	dumpOrders(orders)
	return nil
}
