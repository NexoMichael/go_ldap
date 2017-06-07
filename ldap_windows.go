package ldap

// #include <stdlib.h>
import "C"

import (
	"fmt"
	"strings"
	"syscall"
	"unsafe"
)

var (
	wldap32                      = syscall.NewLazyDLL("Wldap32.dll")
	wldap32_ldap_bind_s          = wldap32.NewProc("ldap_bind_s")
	wldap32_ber_free             = wldap32.NewProc("ber_free")
	wldap32_ldap_connect         = wldap32.NewProc("ldap_connect")
	wldap32_ldap_count_entries   = wldap32.NewProc("ldap_count_entries")
	wldap32_ldap_count_values    = wldap32.NewProc("ldap_count_values")
	wldap32_ldap_get_option      = wldap32.NewProc("ldap_get_option")
	wldap32_ldap_get_values      = wldap32.NewProc("ldap_get_values")
	wldap32_ldap_get_values_len  = wldap32.NewProc("ldap_get_values_len")
	wldap32_ldap_first_entry     = wldap32.NewProc("ldap_first_entry")
	wldap32_ldap_first_attribute = wldap32.NewProc("ldap_first_attribute")
	wldap32_ldap_init            = wldap32.NewProc("ldap_init")
	wldap32_ldap_memfree         = wldap32.NewProc("ldap_memfree")
	wldap32_ldap_msgfree         = wldap32.NewProc("ldap_msgfree")
	wldap32_ldap_next_entry      = wldap32.NewProc("ldap_next_entry")
	wldap32_ldap_next_attribute  = wldap32.NewProc("ldap_next_attribute")
	wldap32_ldap_search_s        = wldap32.NewProc("ldap_search_s")
	wldap32_ldap_set_option      = wldap32.NewProc("ldap_set_option")
	wldap32_ldap_unbind          = wldap32.NewProc("ldap_unbind")
	wldap32_ldap_unbind_s        = wldap32.NewProc("ldap_unbind_s")
	wldap32_ldap_value_free      = wldap32.NewProc("ldap_value_free")
	wldap32_ldap_value_free_len  = wldap32.NewProc("ldap_value_free_len")
)

const (
	LDAP_AUTH_SIMPLE    = 0x80
	LDAP_AUTH_SASL      = 0x83
	LDAP_AUTH_OTHERKIND = 0x86

	LDAP_AUTH_NEGOTIATE = LDAP_AUTH_OTHERKIND | 0x0400
	LDAP_AUTH_SSPI      = LDAP_AUTH_NEGOTIATE

	LDAP_SCOPE_BASE     = 0x0
	LDAP_SCOPE_ONELEVEL = 0x1
	LDAP_SCOPE_SUBTREE  = 0x2

	LDAP_SIZELIMIT_EXCEEDED  = 0x4
	LDAP_INVALID_CREDENTIALS = 0x31
	LDAP_SERVER_DOWN         = 0x51
	LDAP_PARAM_ERROR         = 0x59

	LDAP_OPT_SIZELIMIT        = 0x3
	LDAP_OPT_PROTOCOL_VERSION = 0x11
	LDAP_VERSION3             = 3

	LDAP_OPT_DEBUG_LEVEL = 0x5001 /* debug level */

	LDAP_SUCCESS = 0x0
)

type LDAP uintptr

type LDAPValues uintptr

type LDAPMessage struct {
	msg  uintptr
	ldap LDAP
}

func ldap_error(value uintptr) string {
	switch value {
	case LDAP_SUCCESS:
		{
			return "LDAP_SUCCESS"
		}
	case LDAP_INVALID_CREDENTIALS:
		{
			return "LDAP_INVALID_CREDENTIALS"
		}
	case LDAP_SERVER_DOWN:
		{
			return "LDAP_SERVER_DOWN"
		}
	case LDAP_SIZELIMIT_EXCEEDED:
		{
			return "LDAP_SIZELIMIT_EXCEEDED"
		}
	case LDAP_PARAM_ERROR:
		{
			return "LDAP_PARAM_ERROR"
		}
	}
	return "UNKNOWN: " + fmt.Sprintf("%x", value)
}

func option_name(option int32) string {
	switch option {
	case LDAP_OPT_PROTOCOL_VERSION:
		{
			return "LDAP_OPT_PROTOCOL_VERSION"
		}
	case LDAP_OPT_SIZELIMIT:
		{
			return "LDAP_OPT_SIZELIMIT"
		}
	}
	return "UNKNOWN: " + fmt.Sprintf("%x", option)
}

func ldap_init(hostname string, port uint16) LDAP {
	_hostname := C.CString(hostname)
	defer C.free(unsafe.Pointer(_hostname))
	ldap, _, _ := wldap32_ldap_init.Call(uintptr(unsafe.Pointer(_hostname)), uintptr(C.int(port)))
	//fmt.Println("INIT:", ldap, res2, lastErr)
	return LDAP(ldap)
}

func (ber BERElement) ber_free() {
	wldap32_ber_free.Call(uintptr(ber), uintptr(0))
	//fmt.Println("BER FREE: ", res, res2, lastErr)
}

func mem_free(ptr uintptr) {
	wldap32_ldap_memfree.Call(ptr)
	//fmt.Println("ldap mem free successfully: ", res2, lastErr)
}

func (value LDAPValues) value_free() {
	res, res2, lastErr := wldap32_ldap_value_free.Call(uintptr(value))
	if res == LDAP_SUCCESS {
		//fmt.Println("ldap value free successfully")
	} else {
		panic(fmt.Errorf("ldap_value_free failed with %s %v %v", ldap_error(res), res2, lastErr))
	}
}

func value_free_len(value uintptr) {
	res, res2, lastErr := wldap32_ldap_value_free_len.Call(uintptr(value))
	if res == LDAP_SUCCESS {
		//fmt.Println("ldap value free successfully")
	} else {
		panic(fmt.Errorf("ldap_value_free_len failed with %s %v %v", ldap_error(res), res2, lastErr))
	}
}

func (ldap LDAP) unbind() {
	res, res2, lastErr := wldap32_ldap_unbind.Call(uintptr(ldap))
	if res == LDAP_SUCCESS {
		//fmt.Println("ldap unbind successfully")
	} else {
		panic(fmt.Errorf("ldap_unbind failed with %s %v %v", ldap_error(res), res2, lastErr))
	}
}

func (ldap LDAP) unbind_s() {
	res, res2, lastErr := wldap32_ldap_unbind_s.Call(uintptr(ldap))
	if res == LDAP_SUCCESS {
		//fmt.Println("ldap unbind successfully")
	} else {
		panic(fmt.Errorf("ldap_unbind_s failed with %s %v %v", ldap_error(res), res2, lastErr))
	}
}

func (msg LDAPMessage) msg_free() {
	res, res2, lastErr := wldap32_ldap_msgfree.Call(uintptr(msg.msg))
	if res == LDAP_SUCCESS {
		//fmt.Println("ldap msgfree successfully")
	} else {
		panic(fmt.Errorf("ldap_msgfree failed with %s %v %v", ldap_error(res), res2, lastErr))
	}
}

func (ldap LDAP) set_option(option, value int32) {
	res, _, _ := wldap32_ldap_set_option.Call(uintptr(ldap), uintptr(C.int(option)), uintptr(unsafe.Pointer(&value)))
	if res == LDAP_SUCCESS {
		//fmt.Printf("ldap option %s set to 0x%x\n", option_name(option), value)
	} else {
		ldap.unbind()
		panic(fmt.Errorf("ldap_get_option failed with %s", ldap_error(res)))
	}
}

func (ldap LDAP) get_option(option int32) int32 {
	var result int32
	res, _, _ := wldap32_ldap_get_option.Call(uintptr(ldap), uintptr(C.int(option)), uintptr(unsafe.Pointer(&result)))
	if res == LDAP_SUCCESS {
		//fmt.Printf("ldap option %s value is 0x%x\n", option_name(option), result)
	} else {
		ldap.unbind()
		panic(fmt.Errorf("ldap_get_option failed with %s", ldap_error(res)))
	}
	return result
}

func (ldap LDAP) connect(timeout unsafe.Pointer) int32 {
	var result int32
	res, _, _ := wldap32_ldap_connect.Call(uintptr(ldap), uintptr(unsafe.Pointer(timeout)))
	if res == LDAP_SUCCESS {
		//fmt.Println("ldap connect successfully")
	} else {
		ldap.unbind()
		panic(fmt.Errorf("ldap_connect failed with %s", ldap_error(res)))
	}
	return result
}

func (msg LDAPMessage) count_entries() int32 {
	var result int32
	res, _, _ := wldap32_ldap_count_entries.Call(uintptr(msg.ldap), uintptr(unsafe.Pointer(msg.msg)))
	if int32(res) != -1 {
		//fmt.Println("ldap count entries is", res)
		return int32(res)
	} else {
		panic(fmt.Errorf("ldap_count_entries failed with %s", ldap_error(res)))
	}
	return result
}

func (msg LDAPMessage) first_entry() LDAPMessage {
	res, _, _ := wldap32_ldap_first_entry.Call(uintptr(msg.ldap), uintptr(unsafe.Pointer(msg.msg)))
	if res == 0 {
		//fmt.Printf("ldap_first_entry failed with %s", ldap_error(res))
	} else {
		//fmt.Println("ldap first entry fetched")
	}
	return LDAPMessage{
		msg:  res,
		ldap: msg.ldap,
	}
}

func (msg LDAPMessage) get_values(key uintptr) uintptr {
	res, _, _ := wldap32_ldap_get_values.Call(uintptr(msg.ldap), uintptr(unsafe.Pointer(msg.msg)), key)
	return res
}

func (msg LDAPMessage) get_values_len(key uintptr) uintptr {
	res, _, _ := wldap32_ldap_get_values_len.Call(uintptr(msg.ldap), uintptr(unsafe.Pointer(msg.msg)), key)
	return res
}

type BERElement uintptr

func toString(ptr uintptr) string {
	if ptr == 0 {
		return ""
	}
	res := (*C.char)(unsafe.Pointer(ptr))
	return C.GoString(res)
}

func (msg LDAPMessage) first_attribute(ber *BERElement) uintptr {
	ptr, _, _ := wldap32_ldap_first_attribute.Call(uintptr(msg.ldap), uintptr(unsafe.Pointer(msg.msg)), uintptr(unsafe.Pointer(ber)))
	return ptr
}

func (msg LDAPMessage) next_attribute(ber BERElement) uintptr {
	ptr, _, _ := wldap32_ldap_next_attribute.Call(uintptr(msg.ldap), uintptr(unsafe.Pointer(msg.msg)), uintptr(unsafe.Pointer(ber)))
	return ptr
}

func (msg LDAPMessage) next_entry() LDAPMessage {
	res, _, _ := wldap32_ldap_next_entry.Call(uintptr(msg.ldap), uintptr(unsafe.Pointer(msg.msg)))
	if res == 0 {
		//fmt.Printf("ldap_next_entry failed with %s", ldap_error(res))
	} else {
		//fmt.Println("ldap next entry fetched")
	}
	return LDAPMessage{
		msg:  res,
		ldap: msg.ldap,
	}
}

func (val LDAPValues) count_values() int {
	res, _, _ := wldap32_ldap_count_values.Call(uintptr(val))
	return int(res)
}

func (ldap LDAP) bind_s(username string, password string) {
	var res uintptr

	if username != "" && password != "" {
		_username := C.CString(username)
		defer C.free(unsafe.Pointer(_username))
		_password := C.CString(password)
		defer C.free(unsafe.Pointer(_password))
		// username should be in format "name@domain" not in DN or simple user name format
		res, _, _ = wldap32_ldap_bind_s.Call(uintptr(ldap), uintptr(unsafe.Pointer(_username)), uintptr(unsafe.Pointer(_password)), uintptr(LDAP_AUTH_SIMPLE))
	} else {
		res, _, _ = wldap32_ldap_bind_s.Call(uintptr(ldap), uintptr(unsafe.Pointer(nil)), uintptr(unsafe.Pointer(nil)), uintptr(LDAP_AUTH_NEGOTIATE))
	}

	if res == LDAP_SUCCESS {
		//fmt.Println("ldap_bind_s succeeded")
	} else {
		ldap.unbind()
		panic(fmt.Errorf("ldap_bind_s failed with %s", ldap_error(res)))
	}
}

var (
	// TODO: fix some strange issue with dyncmic creation of this array from attributes list
	_attr = []*C.char{
		C.CString("objectSid"),
		C.CString("displayName"),
		C.CString("objectCategory"),
		C.CString("sAMAccountType"),
		C.CString("name"),
		C.CString("userPrincipalName"),
		C.CString("mail"),
	}
)

func (ldap LDAP) search(base string, filter string, scope int, attributes []string) (LDAPMessage, uintptr) {
	_base := C.CString(base)
	defer C.free(unsafe.Pointer(_base))
	_filter := C.CString(filter)
	defer C.free(unsafe.Pointer(_filter))

	msg := LDAPMessage{ldap: ldap}
	res, _, _ := wldap32_ldap_search_s.Call(
		uintptr(ldap),
		uintptr(unsafe.Pointer(_base)),
		uintptr(C.int(scope)),
		uintptr(unsafe.Pointer(_filter)),
		uintptr(unsafe.Pointer(&_attr[0])),
		uintptr(C.int(0)), // Get both attributes and values
		uintptr(unsafe.Pointer(&msg.msg)),
	)
	if res != LDAP_SUCCESS && res != LDAP_SIZELIMIT_EXCEEDED {
		ldap.unbind()
		panic(fmt.Errorf("ldap_search_s failed with %s", ldap_error(res)))
	}
	//fmt.Println("ldap_search_s succeeded")
	return msg, res
}

type berval struct {
	len uint64
	val unsafe.Pointer
}

func (c *winSpecificConnection) Search(domain string, result interface{}, filter string) error {
	ldap := ldap_init(c.Hostname, c.Port)
	ldap.set_option(LDAP_OPT_PROTOCOL_VERSION, LDAP_VERSION3)
	ldap.set_option(LDAP_OPT_SIZELIMIT, int32(c.SizeLimit))
	ldap.connect(nil)
	ldap.bind_s("", "")
	base := makeDN("DC", strings.Split(domain, "."))

	res, err := newSearchResult(result)
	if err != nil {
		return fmt.Errorf("ldap_windows.search: failed to make search result: %v", err)
	}

	search, searchRes := ldap.search(base, filter, c.Scope, res.tagsList)
	if searchRes != LDAP_SUCCESS && searchRes == LDAP_SIZELIMIT_EXCEEDED {
		err = LdapSizeExceeded
	}

	searchCount := search.count_entries()
	var entry LDAPMessage
	var i int32
	var ber BERElement
	var ppValue LDAPValues

	for i = 0; i < searchCount; i++ {
		if i == 0 {
			entry = search.first_entry()
		} else {
			entry = entry.next_entry()
		}
		if uintptr(entry.msg) == 0 {
			ldap.unbind_s()
			entry.msg_free()
			panic("err")
		}
		//fmt.Printf("ENTRY NUMBER %d \n", i)
		attr := entry.first_attribute(&ber)

		item := res.NewItem()

		for attr != 0 {
			attrName := toString(attr)

			if attrName == "objectSid" {
				value0 := entry.get_values_len(attr)
				b := *(*uintptr)(unsafe.Pointer(value0))
				b1 := (*berval)(unsafe.Pointer(b))
				bytes := C.GoBytes(b1.val, C.int(b1.len))
				item.Set(attrName, []byte(bytes))
				value_free_len(value0)
			} else {
				ppValue = LDAPValues(entry.get_values(attr))
				if ppValue == 0 {
					//fmt.Printf(": [NO ATTRIBUTE VALUE RETURNED]")
				} else {
					valuesCount := ppValue.count_values()
					if valuesCount == 0 {
						//fmt.Printf(": [BAD VALUE LIST]")
					} else {
						value0 := *(*uintptr)(unsafe.Pointer(uintptr(ppValue)))
						//fmt.Printf(": %s :", toString(value0))
						item.Set(attrName, toString(value0))
					}
					//fmt.Printf(" [%d] ", valuesCount)
					ppValue.value_free()
				}
				ppValue = LDAPValues(uintptr(unsafe.Pointer(nil)))
			}
			mem_free(attr)

			attr = entry.next_attribute(ber)
			//fmt.Println()
		}
		res.Add(item)

	}
	ldap.unbind()
	search.msg_free()
	ppValue.value_free()

	return err
}
