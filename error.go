package ldap

import "errors"

var (
	LdapUnsupported  = errors.New("Provided parameters are unsupported on current operating system")
	LdapSizeExceeded = errors.New("Size Limit Exceeded")

	SearchResultNeedPointer = errors.New("Bad result type. Required pointer")
	SearchResultBadType     = errors.New("Bad result type. Required slice or array")
	SearchResultBadElement  = errors.New("Bad result element type. Required struct")
)
