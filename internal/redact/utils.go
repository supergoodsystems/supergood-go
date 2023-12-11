package redact

import (
	"fmt"
	"reflect"
	"strconv"
	"strings"

	remoteconfig "github.com/supergoodsystems/supergood-go/internal/remote-config"
)

// sensitive keys are of the form requestHeaders, responseBody etc. These values must
// be mapped to fields in the parsed supergood event
func formatSensitiveKey(keyPath string) ([]string, error) {
	parts := strings.Split(keyPath, ".")
	remainingParts := []string{}

	switch parts[0] {
	case remoteconfig.RequestHeadersStr:
		remainingParts = append(remainingParts, "Request", "Headers")
	case remoteconfig.RequestBodyStr:
		remainingParts = append(remainingParts, "Request", "Body")
	case remoteconfig.ResponseHeadersStr:
		remainingParts = append(remainingParts, "Response", "Headers")
	case remoteconfig.ResponseBodyStr:
		remainingParts = append(remainingParts, "Response", "Headers")
	default:
		return []string{}, fmt.Errorf("invalid sensitive key value provided: %s", keyPath)
	}
	if len(parts) > 1 {
		remainingParts = append(remainingParts, parts[1:]...)
	}

	return remainingParts, nil
}

func parseArrayIndex(subpath string) int {
	// -2 return type here will be used to represent all indecies
	if subpath == "[]" {
		return -2
	}
	// -1 will represent an error
	i, err := strconv.Atoi(subpath)
	if err != nil {
		return -1
	}
	return i
}

func getSize(v reflect.Value) int {
	size := int(reflect.TypeOf(v).Size())
	switch kind := v.Kind(); {
	case kind == reflect.Interface || kind == reflect.Pointer:
		size += getSize(v.Elem())
	case kind == reflect.Array || kind == reflect.Slice:
		s := reflect.ValueOf(v)
		for i := 0; i < s.Len(); i++ {
			size += getSize(s.Index(i))
		}
	case kind == reflect.Map:
		keys := v.MapKeys()
		for i := range keys {
			size += getSize(keys[i]) + getSize(v.MapIndex(keys[i]))
		}
	case kind == reflect.String:
		size += v.Len()
	case kind == reflect.Struct:
		y := v.NumField()
		fmt.Println(y)
		for i := 0; i < v.NumField(); i++ {
			size += getSize(v.Field(i))
		}
	}
	return size
}
