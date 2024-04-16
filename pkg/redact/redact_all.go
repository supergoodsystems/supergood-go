package redact

import (
	"fmt"
	"reflect"
	"regexp"

	"github.com/supergoodsystems/supergood-go/internal/shared"
	"github.com/supergoodsystems/supergood-go/pkg/event"
	remoteconfig "github.com/supergoodsystems/supergood-go/pkg/remote-config"
)

var shouldTraverseKind = map[reflect.Kind]struct{}{
	reflect.Uintptr:       {},
	reflect.Array:         {},
	reflect.Interface:     {},
	reflect.Map:           {},
	reflect.Pointer:       {},
	reflect.Slice:         {},
	reflect.Struct:        {},
	reflect.UnsafePointer: {},
}

func redactAll(domain string, e *event.Event, sensitiveKeys []remoteconfig.SensitiveKeys) ([]event.RedactedKeyMeta, []error) {
	meta := []event.RedactedKeyMeta{}
	errs := []error{}
	allowedKeys := getAllowedKeys(sensitiveKeys)

	redactRequestHeaderMeta, err := redactAllHelperRecurse(reflect.ValueOf(e.Request.Headers), shared.RequestHeadersStr, allowedKeys)
	errs = append(errs, err...)
	meta = append(meta, redactRequestHeaderMeta...)

	redactRequestBodyMeta, err := redactAllRequestBody(e.Request, shared.RequestBodyStr, allowedKeys)
	errs = append(errs, err...)
	meta = append(meta, redactRequestBodyMeta...)

	redactResponseHeaderMeta, err := redactAllHelperRecurse(reflect.ValueOf(&e.Response.Headers), shared.ResponseHeadersStr, allowedKeys)
	errs = append(errs, err...)
	meta = append(meta, redactResponseHeaderMeta...)

	redactResponseBodyMeta, err := redactAllResponseBody(e.Response, shared.ResponseBodyStr, allowedKeys)
	errs = append(errs, err...)
	meta = append(meta, redactResponseBodyMeta...)

	return meta, errs
}

// NOTE: duplicate body will attempt to cast to map[string]interface{} in the case it cannot
// it will cast the response into a string. In the case the body is returned as a string, the
// reflected value is not settable - and is why this check is in place below
func redactAllResponseBody(response *event.Response, path string, allowedKeys map[string]struct{}) ([]event.RedactedKeyMeta, []error) {
	errs := []error{}
	result := []event.RedactedKeyMeta{}
	if response.Body == nil {
		return result, errs
	}

	v := reflect.ValueOf(response.Body)
	if !v.IsValid() {
		errs = append(errs, fmt.Errorf("redact-all: invalid reflected value at path: %s", path))
		return []event.RedactedKeyMeta{}, errs
	}
	if v.Type().Kind() == reflect.String {
		result := prepareOutput(v, path)
		response.Body = ""
		return result, nil
	}
	return redactAllHelperRecurse(v, path, allowedKeys)
}

// NOTE: duplicate body will attempt to cast to map[string]interface{} in the case it cannot
// it will cast the request into a string. In the case the body is returned as a string, the
// reflected value is not settable - and is why this check is in place below
func redactAllRequestBody(request *event.Request, path string, allowedKeys map[string]struct{}) ([]event.RedactedKeyMeta, []error) {
	errs := []error{}
	result := []event.RedactedKeyMeta{}
	if request.Body == nil {
		return result, errs
	}
	v := reflect.ValueOf(request.Body)
	if !v.IsValid() {
		errs = append(errs, fmt.Errorf("redact-all: invalid reflected value at path: %s", path))
		return result, errs
	}
	if v.Type().Kind() == reflect.String {
		result := prepareOutput(v, path)
		request.Body = ""
		return result, errs
	}
	return redactAllHelperRecurse(v, path, allowedKeys)
}

func redactAllHelperRecurse(v reflect.Value, path string, allowedKeys map[string]struct{}) ([]event.RedactedKeyMeta, []error) {
	errs := []error{}
	if !v.IsValid() {
		errs = append(errs, fmt.Errorf("redact-all: invalid reflected value at path: %s", path))
		return []event.RedactedKeyMeta{}, errs
	}
	switch v.Type().Kind() {
	case reflect.Ptr, reflect.Interface:
		if v.IsNil() {
			return []event.RedactedKeyMeta{}, nil
		}
		return redactAllHelperRecurse(v.Elem(), path, allowedKeys)

	case reflect.Struct:
		// NOTE: duplicate body should never return a struct. It will create a map[interface]interface{} instead
		results := []event.RedactedKeyMeta{}
		for i := 0; i < v.NumField(); i++ {
			result, err := redactAllHelperRecurse(v.Field(i), v.Field(i).Kind().String(), allowedKeys) // <- not sure yet how to grab the name of the key using reflection
			if err != nil {
				return results, err
			}
			results = append(results, result...)
		}
		return results, nil

	case reflect.Map:
		if v.IsNil() {
			return []event.RedactedKeyMeta{}, nil
		}

		results := []event.RedactedKeyMeta{}
		for _, key := range v.MapKeys() {
			mapVal := v.MapIndex(key)
			path := path + "." + key.String()
			if !mapVal.IsValid() {
				errs = append(errs, fmt.Errorf("redact-all: invalid reflected value at path: %s", path))
				continue
			}

			ok := shouldTraverse(mapVal)
			if !ok {
				if mapVal.Type() == nil {
					continue
				}
				if !shouldRedact(path, allowedKeys) {
					continue
				}
				v.SetMapIndex(key, reflect.Zero(mapVal.Type()))
				results = append(results, prepareOutput(mapVal, path)...)
			} else {
				result, err := redactAllHelperRecurse(mapVal, path, allowedKeys)
				errs = append(errs, err...)
				results = append(results, result...)
			}

		}
		return results, errs

	case reflect.Array, reflect.Slice:
		results := []event.RedactedKeyMeta{}
		if v.Len() == 0 || (v.Kind() == reflect.Slice && v.IsNil()) {
			return results, nil
		}

		if ok := shouldTraverse(v.Index(0)); !ok {
			if !v.CanSet() {
				errs = append(errs, fmt.Errorf("redact-all: invalid reflected value at path: %s", path))
				return []event.RedactedKeyMeta{}, errs
			} else {
				if !shouldRedact(path, allowedKeys) {
					return []event.RedactedKeyMeta{}, errs
				}
				result := prepareOutput(v, path)
				v.Set(reflect.Zero(v.Type()))
				return result, errs
			}
		}

		for i := 0; i < v.Len(); i++ {
			result, err := redactAllHelperRecurse(v.Index(i), fmt.Sprintf("%s[%d]", path, i), allowedKeys)
			errs = append(errs, err...)
			results = append(results, result...)
		}
		return results, errs

	default:
		if !v.CanSet() {
			errs = append(errs, fmt.Errorf("redact-all: invalid reflected value at path: %s", path))
			return []event.RedactedKeyMeta{}, errs
		}
		if !shouldRedact(path, allowedKeys) {
			return []event.RedactedKeyMeta{}, errs
		}
		result := prepareOutput(v, path)
		v.Set(reflect.Zero(v.Type()))
		return result, errs
	}
}

func shouldTraverse(v reflect.Value) bool {
	switch v.Kind() {
	// NOTE: below is required to redact arrays, slices, and maps successfully.
	// if you recurse into the elements of an array, slice or map with primitive values, they are not settable
	// therefore, you'll need to know whether to redact at a layer above
	case reflect.Array, reflect.Slice:
		if v.Len() == 0 {
			return false
		}
		valAtIndex := v.Index(0)
		k := valAtIndex.Kind()
		if k == reflect.Interface || k == reflect.Pointer {
			valAtIndex = valAtIndex.Elem()
		}
		_, ok := shouldTraverseKind[valAtIndex.Kind()]
		return ok

	case reflect.Interface:
		return shouldTraverse(v.Elem())

	case reflect.Uintptr, reflect.Map, reflect.Pointer, reflect.Struct, reflect.UnsafePointer:
		return true
	default:
		return false
	}
}

func prepareOutput(v reflect.Value, path string) []event.RedactedKeyMeta {
	size := getSize(v)
	val := v
	if val.IsValid() && (val.Type().Kind() == reflect.Interface || val.Type().Kind() == reflect.Pointer) {
		val = v.Elem()
	}
	kind := "invalid"
	if val.IsValid() {
		kind = formatKind(val.Type().Kind())
	}
	return []event.RedactedKeyMeta{
		{
			KeyPath: path,
			Length:  size,
			Type:    kind,
		},
	}
}

func getAllowedKeys(sensitiveKeys []remoteconfig.SensitiveKeys) map[string]struct{} {
	keysToAllow := map[string]struct{}{}
	for _, sensitiveKey := range sensitiveKeys {
		if sensitiveKey.Action == "ALLOW" {
			keysToAllow[sensitiveKey.KeyPath] = struct{}{}
		}
	}
	return keysToAllow
}

func shouldRedact(path string, allowedKeys map[string]struct{}) bool {
	if _, allowed := allowedKeys[path]; allowed {
		return false
	}
	regexp, err := regexp.Compile(`\[\d+\]`)
	if err != nil {
		return true
	}

	cleanedPath := regexp.ReplaceAllString(path, "[]")
	if _, allowed := allowedKeys[cleanedPath]; allowed {
		return false
	}

	return true
}
