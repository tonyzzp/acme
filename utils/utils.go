package utils

import (
	"crypto/md5"
	"encoding/hex"
	"encoding/json"
	"io"
	"log"
	"os"
	"strings"
)

func SliceFind[T any](array []T, predict func(t T) bool) *T {
	for _, v := range array {
		if predict(v) {
			return &v
		}
	}
	return nil
}

func SliceMap[T any, R any](array []T, trans func(t T) R) []R {
	rtn := make([]R, 0)
	for _, v := range array {
		rtn = append(rtn, trans(v))
	}
	return rtn
}

func SliceFilter[T any](array []T, filter func(t T) bool) []T {
	rtn := make([]T, 0)
	for _, v := range array {
		if filter(v) {
			rtn = append(rtn, v)
		}
	}
	return rtn
}

func DumpJson(data any, writer io.Writer) {
	bs, e := json.MarshalIndent(data, "", "    ")
	if e != nil {
		log.Println(e)
		writer.Write([]byte(e.Error()))
	} else {
		writer.Write(bs)
	}
	writer.Write([]byte("\n"))
}

func FileExists(file string) bool {
	_, e := os.Stat(file)
	return e == nil
}

func Md5String(data []byte) string {
	bs := md5.Sum(data)
	return strings.ToLower(hex.EncodeToString(bs[:]))
}
