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
// NOTE: Redact is expecting that the endpoint Id for the event has been successfully populated
// during event
func Redact(events []*event.Event, rc *remoteconfig.RemoteConfig) []error {
	var errs []error
	for _, e := range events {
		domain := domainutils.GetDomainFromHost(e.Request.URL)
		endpoints := rc.Get(domain)
		if len(endpoints) == 0 {
			continue
		}
		endpoint, ok := endpoints[e.MetaData.EndpointId]
		if !ok {
			continue
		}

		for _, sensitiveKey := range endpoint.SensitiveKeys {
			formattedParts, err := formatSensitiveKey(sensitiveKey.KeyPath)
			if err != nil {
				errs = append(errs, err)
				continue
			}
			meta, err := redactEvent(sensitiveKey.KeyPath, formattedParts, e)
			if err != nil {
				errs = append(errs, err)
				continue
			}
			e.MetaData.SensitiveKeys = append(e.MetaData.SensitiveKeys, meta...)
		}
	}
	return errs
}

func redactEvent(originalPath string, path []string, v any) ([]event.RedactedKeyMeta, error) {
	return redactEventHelper(originalPath, path, reflect.ValueOf(v).Elem(), "")
}

// redactEventHelper recursively redacts fields based off a provided path
// originalPath: represents the original full path - used for logging
// path: is the split stringed representation of the fullpath. contains the remaining path elements to be traversed
// v: is the reflected value at the current path
// createdPath: is the recursively built path. Difference between fullpath and createdpath is that createdPath will contain array indexes
func redactEventHelper(originalPath string, pathParts []string, v reflect.Value, createdPath string) ([]event.RedactedKeyMeta, error) {
	if !v.IsValid() {
		return nil, fmt.Errorf("unable to find key at sensitive key provided path: %s", originalPath)
	}
	if len(pathParts) == 0 {
		size := getSize(v)
		if !v.CanSet() {
			return nil, fmt.Errorf("unable to redact at sensitive key provided path: %s", originalPath)
		}
		v.Set(reflect.Zero(v.Type()))
		return []event.RedactedKeyMeta{
			{
				KeyPath: reformatSensitiveKeyPath(createdPath),
				Length:  size,
				Type:    v.Type().Kind().String(),
			},
		}, nil
	} else {
		switch v.Type().Kind() {
		case reflect.Ptr, reflect.Interface:
			return redactEventHelper(originalPath, pathParts, v.Elem(), createdPath)

		case reflect.Struct:
			return redactEventHelper(originalPath, pathParts[1:], v.FieldByName(pathParts[0]), formatFieldPathPart(createdPath, pathParts[0]))

		case reflect.Map:
			// You can't mutate elements of a map, but as a special case if we just
			// want to zero out one of the elements of the map, we can just do that
			// here.
			idx := reflect.ValueOf(pathParts[0])
			mapVal := v.MapIndex(idx)
			if !mapVal.IsValid() {
				return nil, fmt.Errorf("unable to find key at sensitive key provided path: %s", originalPath)
			}
			if len(pathParts) == 1 {
				size := getSize(mapVal)
				// Attempting to marshal into underlying type
				objKind := mapVal.Type().Kind().String()
				if mapVal.Kind() == reflect.Interface || mapVal.Kind() == reflect.Pointer {
					objKind = mapVal.Elem().Type().Kind().String()
				}
				v.SetMapIndex(idx, reflect.Zero(v.Type().Elem()))
				return []event.RedactedKeyMeta{
					{
						KeyPath: reformatSensitiveKeyPath(formatFieldPathPart(createdPath, pathParts[0])),
						Length:  size,
						Type:    objKind,
					},
				}, nil
			} else {
				return redactEventHelper(originalPath, pathParts[1:], mapVal, formatFieldPathPart(createdPath, pathParts[0]))
			}

		case reflect.Array, reflect.Slice:
			idx := parseArrayIndex(pathParts[0])
			if idx == -1 {
				return nil, fmt.Errorf("invalid index value provided at location")
			}

			results := []event.RedactedKeyMeta{}
			for i := 0; i < v.Len(); i++ {
				result, err := redactEventHelper(originalPath, pathParts[1:], v.Index(i), formatArrayPathPart(createdPath, i))
				if err != nil {
					return results, err
				}
				results = append(results, result...)
			}
			return results, nil

		default:
			return nil, fmt.Errorf("redact.Redact: unsupported type %v", v.Type().String())
		}
	}
}
