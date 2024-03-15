package redact

import (
	"fmt"
	"reflect"

	"github.com/supergoodsystems/supergood-go/pkg/event"
)

func redactPath(domain string, url string, originalPath string, path []string, v any) ([]event.RedactedKeyMeta, error) {
	return redactPathHelper(domain, url, originalPath, path, reflect.ValueOf(v).Elem(), "")
}

// redactEventHelper recursively redacts fields based off a provided path
// originalPath: represents the original full path - used for logging
// path: is the split stringed representation of the fullpath. contains the remaining path elements to be traversed
// v: is the reflected value at the current path
// createdPath: is the recursively built path. Difference between fullpath and createdpath is that createdPath will contain array indexes
func redactPathHelper(domain, url, originalPath string, pathParts []string, v reflect.Value, createdPath string) ([]event.RedactedKeyMeta, error) {
	if !v.IsValid() {
		return nil, fmt.Errorf("unable to find key at sensitive key for URL: %s, domain: %s, provided path: %s", domain, url, originalPath)
	}
	if len(pathParts) == 0 {
		size := getSize(v)
		if !v.CanSet() {
			return nil, fmt.Errorf("unable to redact at sensitive key for URL: %s, domain: %s, path: %s", domain, url, originalPath)
		}
		v.Set(reflect.Zero(v.Type()))
		return []event.RedactedKeyMeta{
			{
				KeyPath: reformatSensitiveKeyPath(createdPath),
				Length:  size,
				Type:    formatKind(v.Type().Kind()),
			},
		}, nil
	} else {
		switch v.Type().Kind() {
		case reflect.Ptr, reflect.Interface:
			return redactPathHelper(domain, url, originalPath, pathParts, v.Elem(), createdPath)

		case reflect.Struct:
			return redactPathHelper(domain, url, originalPath, pathParts[1:], v.FieldByName(pathParts[0]), formatFieldPathPart(createdPath, pathParts[0]))

		case reflect.Map:
			// You can't mutate elements of a map, but as a special case if we just
			// want to zero out one of the elements of the map, we can just do that
			// here.
			idx := reflect.ValueOf(pathParts[0])
			mapVal := v.MapIndex(idx)
			if !mapVal.IsValid() {
				return nil, fmt.Errorf("unable to find key at sensitive key for URL: %s, domain: %s, path: %s", url, domain, originalPath)
			}
			if len(pathParts) == 1 {
				size := getSize(mapVal)
				objKind := mapVal.Type().Kind()
				// sometimes mapVals are interfaces or pointers - make sure to get the underlying type
				if mapVal.Kind() == reflect.Interface || mapVal.Kind() == reflect.Pointer {
					if !mapVal.Elem().IsValid() {
						objKind = reflect.Invalid
					} else {
						objKind = mapVal.Elem().Type().Kind()
					}
				}
				v.SetMapIndex(idx, reflect.Zero(v.Type().Elem()))
				return []event.RedactedKeyMeta{
					{
						KeyPath: reformatSensitiveKeyPath(formatFieldPathPart(createdPath, pathParts[0])),
						Length:  size,
						Type:    formatKind(objKind),
					},
				}, nil
			} else {
				return redactPathHelper(domain, url, originalPath, pathParts[1:], mapVal, formatFieldPathPart(createdPath, pathParts[0]))
			}

		case reflect.Array, reflect.Slice:
			idx := parseArrayIndex(pathParts[0])
			if idx == -1 {
				return nil, fmt.Errorf("invalid index value provided at location")
			}

			results := []event.RedactedKeyMeta{}
			for i := 0; i < v.Len(); i++ {
				result, err := redactPathHelper(domain, url, originalPath, pathParts[1:], v.Index(i), formatArrayPathPart(createdPath, i))
				if err != nil {
					return results, err
				}
				results = append(results, result...)
			}
			return results, nil

		default:
			return nil, fmt.Errorf("redact.Redact: unsupported type %v for URL: %s, domain: %s, path: %s", v.Type().String(), url, domain, originalPath)
		}
	}
}
