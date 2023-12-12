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
		remainingParts = append(remainingParts, "Response", "Body")
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

// Note: this is a naive way of generating the size of a reflected object
func getSize(v reflect.Value) int {
	size := int(reflect.TypeOf(v).Size())
	switch v.Kind() {
	case reflect.Interface, reflect.Pointer:
		size += getSize(v.Elem())
	case reflect.Array, reflect.Slice:
		s := reflect.ValueOf(v)
		for i := 0; i < s.Len(); i++ {
			size += getSize(s.Index(i))
		}
	case reflect.Map:
		keys := v.MapKeys()
		for i := range keys {
			size += getSize(keys[i]) + getSize(v.MapIndex(keys[i]))
		}
	case reflect.String:
		size += v.Len()
	case reflect.Struct:
		for i := 0; i < v.NumField(); i++ {
			size += getSize(v.Field(i))
		}
	}
	return size
}
