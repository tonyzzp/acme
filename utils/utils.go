package utils

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
