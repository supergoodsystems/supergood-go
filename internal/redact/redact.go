package redact

import (
	"fmt"
	"reflect"

	domainutils "github.com/supergoodsystems/supergood-go/internal/domain-utils"
	"github.com/supergoodsystems/supergood-go/internal/event"
	remoteconfig "github.com/supergoodsystems/supergood-go/internal/remote-config"
)

// Redact removes the sensitive keys provided in remote config cache
// NOTE: Redact modifies events and appends redacted info to the event object
func Redact(events []*event.Event, rc *remoteconfig.RemoteConfig, handleError func(error)) {
	for _, e := range events {
		domain := domainutils.GetDomainFromHost(e.Request.URL)

		endpoints := rc.Get(domain)
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
					continue
				}
				meta, err := redactEvent(sensitiveKey.KeyPath, formattedParts, e)
				if err != nil {
					handleError(err)
					continue
				}
				e.MetaData.SensitiveKeys = append(e.MetaData.SensitiveKeys, meta...)
			}
		}
	}
}

func redactEvent(fullpath string, path []string, v any) ([]event.RedactedKeyMeta, error) {
	return redactEventHelper(fullpath, path, reflect.ValueOf(v).Elem())
}

func redactEventHelper(fullpath string, path []string, v reflect.Value) ([]event.RedactedKeyMeta, error) {
	if len(path) == 0 {
		size := getSize(v)
		v.Set(reflect.Zero(v.Type()))
		return []event.RedactedKeyMeta{
			{
				KeyPath: fullpath,
				Length:  size,
				Type:    v.Type().Kind().String(),
			},
		}, nil
	} else {
		switch v.Type().Kind() {
		case reflect.Ptr, reflect.Interface:
			return redactEventHelper(fullpath, path, v.Elem())

		case reflect.Struct:
			return redactEventHelper(fullpath, path[1:], v.FieldByName(path[0]))

		case reflect.Map:
			// You can't mutate elements of a map, but as a special case if we just
			// want to zero out one of the elements of the map, we can just do that
			// here.
			idx := reflect.ValueOf(path[0])
			mapVal := v.MapIndex(idx)
			if len(path) == 1 {
				size := getSize(mapVal)
				v.SetMapIndex(idx, reflect.Zero(v.Type().Elem()))
				return []event.RedactedKeyMeta{
					{
						KeyPath: fullpath,
						Length:  size,
						Type:    v.Type().Kind().String(),
					},
				}, nil
			} else {
				return redactEventHelper(fullpath, path[1:], mapVal)
			}

		case reflect.Array, reflect.Slice:
			idx := parseArrayIndex(path[0])
			if idx > -1 {
				return redactEventHelper(fullpath, path, v.Index(idx))
			} else if idx == -1 {
				results := []event.RedactedKeyMeta{}
				for i := 0; i < v.Len(); i++ {
					result, err := redactEventHelper(fullpath, path, v.Index(i))
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
