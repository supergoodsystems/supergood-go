package redact

import (
	"fmt"
	"reflect"

	"github.com/supergoodsystems/supergood-go/internal/shared"
	"github.com/supergoodsystems/supergood-go/pkg/event"
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

func redactAll(domain, url string, e *event.Event) ([]event.RedactedKeyMeta, []error) {
	meta := []event.RedactedKeyMeta{}
	errs := []error{}
	redactRequestHeaderMeta, err := redactAllHelperRecurse(reflect.ValueOf(e.Request.Headers), shared.RequestHeadersStr)
	if err != nil {
		errs = append(errs, err)
	} else {
		meta = append(meta, redactRequestHeaderMeta...)
	}

	redactRequestBodyMeta, err := redactAllRequestBody(e.Request, shared.RequestBodyStr)
	if err != nil {
		errs = append(errs, err)
	} else {
		meta = append(meta, redactRequestBodyMeta...)
	}

	redactResponseHeaderMeta, err := redactAllHelperRecurse(reflect.ValueOf(e.Response.Headers), shared.ResponseHeadersStr)
	if err != nil {
		errs = append(errs, err)
	} else {
		meta = append(meta, redactResponseHeaderMeta...)
	}

	redactResponseBodyMeta, err := redactAllResponseBody(e.Response, shared.ResponseBodyStr)
	if err != nil {
		errs = append(errs, err)
	} else {
		meta = append(meta, redactResponseBodyMeta...)
	}

	return meta, errs
}

func redactAllResponseBody(response *event.Response, path string) ([]event.RedactedKeyMeta, error) {
	v := reflect.ValueOf(response.Body)
	if !v.IsValid() {
		return prepareInvalidOutput(path), nil
	}
	if v.Type().Kind() == reflect.String {
		result := prepareOutput(v, path)
		response.Body = ""
		return result, nil
	}
	return redactAllHelperRecurse(reflect.ValueOf(response.Body), path)
}

func redactAllRequestBody(request *event.Request, path string) ([]event.RedactedKeyMeta, error) {
	v := reflect.ValueOf(request.Body)
	if !v.IsValid() {
		return prepareInvalidOutput(path), nil
	}
	if v.Type().Kind() == reflect.String {
		result := prepareOutput(v, path)
		request.Body = ""
		return result, nil
	}
	return redactAllHelperRecurse(reflect.ValueOf(request.Body), path)
}

func redactAllHelperRecurse(v reflect.Value, path string) ([]event.RedactedKeyMeta, error) {
	if !v.IsValid() {
		return []event.RedactedKeyMeta{}, nil
	}
	switch v.Type().Kind() {
	case reflect.Ptr, reflect.Interface:
		if v.IsNil() {
			return []event.RedactedKeyMeta{}, nil
		}
		return redactAllHelperRecurse(v.Elem(), path)

	case reflect.Struct:
		results := []event.RedactedKeyMeta{}
		for i := 0; i < v.NumField(); i++ {
			result, err := redactAllHelperRecurse(v.Field(i), v.Field(i).Kind().String())
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
				return []event.RedactedKeyMeta{}, nil
			}

			ok := shouldTraverse(mapVal)
			if !ok {
				if mapVal.Type() == nil {
					continue
				}
				v.SetMapIndex(key, reflect.Zero(mapVal.Type()))
				results = append(results, prepareOutput(mapVal, path)...)
			} else {
				result, err := redactAllHelperRecurse(mapVal, path)
				if err != nil {
					return results, err
				}
				results = append(results, result...)
			}

		}
		return results, nil

	case reflect.Array, reflect.Slice:
		results := []event.RedactedKeyMeta{}
		if v.Len() == 0 || (v.Kind() == reflect.Slice && v.IsNil()) {
			return results, nil
		}

		if ok := shouldTraverse(v.Index(0)); !ok {
			if !v.CanSet() {
				return results, nil
			} else {
				result := prepareOutput(v, path)
				v.Set(reflect.Zero(v.Type()))
				return result, nil
			}
		}

		for i := 0; i < v.Len(); i++ {
			result, err := redactAllHelperRecurse(v.Index(i), fmt.Sprintf("%s[%d]", path, i))
			if err != nil {
				return results, err
			}
			results = append(results, result...)
		}
		return results, nil

	default:
		if !v.CanSet() {
			return []event.RedactedKeyMeta{}, nil
		}
		result := prepareOutput(v, path)
		v.Set(reflect.Zero(v.Type()))
		return result, nil
	}
}

func shouldTraverse(v reflect.Value) bool {
	switch v.Kind() {
	// NOTE: below is required to redact arrays and slices.
	// Arrays, slices with primitive values cannot be successfully nullified because
	// the reflected value is not addressable
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

func prepareInvalidOutput(path string) []event.RedactedKeyMeta {
	return []event.RedactedKeyMeta{
		{
			KeyPath: path,
			Length:  0,
			Type:    "invalid",
		},
	}
}

func prepareOutput(v reflect.Value, path string) []event.RedactedKeyMeta {
	size := getSize(v)
	return []event.RedactedKeyMeta{
		{
			KeyPath: path,
			Length:  size,
			Type:    formatKind(v.Type().Kind()),
		},
	}
}
