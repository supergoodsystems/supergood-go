package redact

import (
	"fmt"
	"reflect"
	"sync"

	domainutils "github.com/supergoodsystems/supergood-go/internal/domain-utils"
	"github.com/supergoodsystems/supergood-go/internal/event"
	remoteconfig "github.com/supergoodsystems/supergood-go/internal/remote-config"
)

// Redact removes the sensitive keys provided in remote config cache
// NOTE: Redact modifies events and appends redacted info to the event object
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
				meta, err := redactEvent(formattedParts, e)
				if err != nil {
					handleError(err)
				}
				e.MetaData.SensitiveKeys = append(e.MetaData.SensitiveKeys, meta...)
			}
		}
	}
	return nil
}

func redactEvent(path []string, v interface{}) ([]event.RedactedKeyMeta, error) {
	return redactEventHelper(path, reflect.ValueOf(v).Elem())
}

func redactEventHelper(path []string, v reflect.Value) ([]event.RedactedKeyMeta, error) {
	if len(path) == 0 {
		size := getSize(v)
		v.Set(reflect.Zero(v.Type()))
		return []event.RedactedKeyMeta{
			{
				Length: size,
				Type:   v.Type().Kind().String(),
			},
		}, nil
	} else {
		switch v.Type().Kind() {
		case reflect.Ptr:
			return redactEventHelper(path, v.Elem())

		case reflect.Struct:
			return redactEventHelper(path[1:], v.FieldByName(path[0]))

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
				return []event.RedactedKeyMeta{
					{
						Length: size,
						Type:   v.Type().Kind().String(),
					},
				}, nil
			} else {
				return redactEventHelper(path[1:], mapVal)
			}

		case reflect.Array, reflect.Slice:
			idx := parseArrayIndex(path[0])
			if idx > -1 {
				return redactEventHelper(path, v.Index(idx))
			} else if idx == -1 {
				results := []event.RedactedKeyMeta{}
				for i := 0; i < v.Len(); i++ {
					result, err := redactEventHelper(path, v.Index(i))
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
