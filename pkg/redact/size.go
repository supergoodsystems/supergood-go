package redact

import "reflect"

// Note: this is a naive way of generating the size of a reflected object
func getSize(v reflect.Value) int {
	size := 0
	if !v.IsValid() {
		return size
	}
	switch v.Kind() {
	case reflect.Interface, reflect.Pointer:
		size += getSize(v.Elem())
	case reflect.Array, reflect.Slice:
		for i := 0; i < v.Len(); i++ {
			size += getSize(v.Index(i))
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
	default:
		if !v.IsZero() || v.Type() != nil {
			size += int(v.Type().Size())
		}
	}
	return size
}
