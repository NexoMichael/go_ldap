package ldap

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"reflect"
	"strings"
)

func makeDN(attribute string, components []string) string {
	if attribute != "" {
		for i := 0; i < len(components); i++ {
			components[i] = attribute + "=" + components[i]
		}
	}
	return strings.Join(components, ",")
}

// SID or a Security Identifier is a unique, immutable identifier of a user, user group, or other security principal.
type SID []byte

var (
	sidItem SID
)

func (sid SID) String() string {
	if sid == nil || len(sid) == 0 || len(sid) < 8 || len(sid)%4 != 0 {
		return ""
	}
	result := fmt.Sprintf("S-%x", sid[0])
	c := int(sid[1])
	r := bytes.NewReader(sid)
	var l uint64
	binary.Read(r, binary.BigEndian, &l)
	l = l & 0xFFFFFFFFFFFF
	result = result + fmt.Sprintf("-%d", l)
	for i := 0; i < c; i++ {
		var s uint32
		binary.Read(r, binary.LittleEndian, &s)
		s = s & 0xFFFFFFFF
		result = result + fmt.Sprintf("-%d", s)
	}
	return result
}

type searchResult struct {
	obj        reflect.Value
	objType    reflect.Type
	resultType reflect.Type
	itemType   reflect.Type

	// List of tag fields
	tagFields map[string]string
	tagsList  []string
}

type searchItem struct {
	item      reflect.Value
	tagFields map[string]string
}

func newSearchResult(result interface{}) (*searchResult, error) {
	res := searchResult{
		obj: reflect.ValueOf(result),
	}
	res.objType = reflect.TypeOf(result)
	if res.objType.Kind() != reflect.Ptr {
		return nil, SearchResultNeedPointer
	}

	res.resultType = res.objType.Elem()
	if res.resultType.Kind() != reflect.Slice && res.resultType.Kind() != reflect.Array {
		return nil, SearchResultBadType
	}

	res.itemType = res.resultType.Elem()
	if res.itemType.Kind() != reflect.Struct {
		return nil, errors.New("Bad result element type. Required struct")
	}

	res.tagFields = make(map[string]string, res.itemType.NumField())
	for i := 0; i < res.itemType.NumField(); i++ {
		field := res.itemType.Field(i)
		tag := field.Tag.Get("ldap")
		if tag == "" {
			continue // field has no "ldap" tag so it should be simply skipped
		}
		res.tagFields[tag] = field.Name
	}
	res.tagsList = make([]string, 0, len(res.tagFields))
	for tag := range res.tagFields {
		res.tagsList = append(res.tagsList, tag)
	}

	return &res, nil
}

func (res *searchResult) NewItem() searchItem {
	return searchItem{
		tagFields: res.tagFields,
		item:      reflect.Indirect(reflect.New(res.obj.Elem().Type().Elem())),
	}
}

func (res *searchResult) Add(item searchItem) {
	slice := res.obj.Elem()
	slice.Set(reflect.Append(slice, item.item))
}

func (item *searchItem) Set(attrName string, value interface{}) {
	valueObject := item.item.FieldByName(item.tagFields[attrName])
	switch valueObject.Kind() {
	case reflect.String:
		valueObject.SetString(value.(string))
	case reflect.TypeOf(sidItem).Kind():
		var sid SID
		switch value.(type) {
		case string:
			sid = SID([]byte(value.(string)))
		default:
			sid = SID(value.([]byte))
		}
		valueObject.Set(reflect.ValueOf(sid))
	}
}
