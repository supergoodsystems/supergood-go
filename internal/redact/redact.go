package redact

import (
	"bytes"
	"encoding/gob"
	"fmt"
	"reflect"
	"strconv"
	"strings"
	"sync"

	domainutils "github.com/supergoodsystems/supergood-go/internal/domain-utils"
	"github.com/supergoodsystems/supergood-go/internal/event"
	remoteconfig "github.com/supergoodsystems/supergood-go/internal/remote-config"
)

// Redact removes the sensitive keys provided in remote config cache
func Redact(events []*event.Event, mutex *sync.RWMutex, cache map[string][]remoteconfig.EndpointCacheVal, handleError func(error)) error {
	mutex.RLock()
	defer mutex.RUnlock()

	for _, e := range events {
		domain := domainutils.GetDomainFromHost(e.Request.URL)
		endpoints := cache[domain]
		if len(endpoints) == 0 {
			continue
		}
		for _, endpoint := range endpoints {
			if len(endpoint.SensitiveKeys) == 0 {
				continue
			}
			testVal, err := event.StringifyAtLocation(e, endpoint.Location)
			if err != nil {
				handleError(err)
				continue
			}
			testByteArray := []byte(fmt.Sprintf("%v", testVal))
			match := endpoint.Regex.Match(testByteArray)
			if !match {
				continue
			}

			for _, sensitiveKey := range endpoint.SensitiveKeys {
				formattedParts, err := formatSensitiveKey(sensitiveKey.KeyPath)
				if err != nil {
					handleError(err)
				}
				redact(formattedParts, e)

				if err != nil {
					handleError(err)
				}
			}
		}
	}
	return nil
}

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

func redact(path []string, v interface{}) ([]RedactedMeta, error) {
	return redacthelper(path, reflect.ValueOf(v).Elem())
}

func redacthelper(path []string, v reflect.Value) ([]RedactedMeta, error) {
	if len(path) == 0 {
		size := getSize(v)
		v.Set(reflect.Zero(v.Type()))
		return []RedactedMeta{
			{
				Size: size,
				Type: v.Type().Kind().String(),
			},
		}, nil
	} else {
		switch v.Type().Kind() {
		case reflect.Ptr:
			return redact(path, v.Elem())

		case reflect.Struct:
			return redact(path[1:], v.FieldByName(path[0]))

		case reflect.Map:
			// You can't mutate elements of a map, but as a special case if we just
			// want to zero out one of the elements of the map, we can just do that
			// here.
			idx := reflect.ValueOf(path[0])
			mapVal := v.MapIndex(idx)
			if len(path) == 1 {
				idx := reflect.ValueOf(path[0])
				size := getSize(mapVal)
				v.SetMapIndex(idx, reflect.Zero(v.Type().Elem()))
				return []RedactedMeta{
					{
						Size: size,
						Type: v.Type().Kind().String(),
					},
				}, nil
			} else {
				return redact(path[1:], mapVal)
			}

		case reflect.Array, reflect.Slice:
			idx := parseArrayIndex(path[0])
			if idx > -1 {
				return redact(path, v.Index(idx))
			} else if idx == -1 {
				results := []RedactedMeta{}
				for i := 0; i < v.Len(); i++ {
					result, err := redact(path, v.Index(i))
					if err != nil {
						return results, err
					}
					results = append(results, result...)
				}
				return results, nil
			} else {
				return nil, fmt.Errorf("invalid index value provided at location")
			}

		default:
			return nil, fmt.Errorf("redact.Redact: unsupported type %v", v.Type().String())
		}
	}
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

func getSize(obj any) int {
	var buf bytes.Buffer
	enc := gob.NewEncoder(&buf)
	err := enc.Encode(obj)
	if err != nil {
		return -1
	}
	return buf.Len()

}
