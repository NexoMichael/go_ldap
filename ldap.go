package ldap

import (
	"fmt"
	"runtime"
	"strings"

	"gopkg.in/ldap.v2"
)

const (
	LdapPort = 389
)

type ldapConnection struct {
	Config
}

type winSpecificConnection struct {
	Config
}

type search interface {
	Search(domain string, result interface{}, filter string) error
}

// Config defines LDAP connection configuration
type Config struct {
	Hostname     string
	Port         uint16
	BindDN       string
	BindPassword string

	Scope     int
	SizeLimit uint16
	TimeLimit uint16

	OnlyCurrentDomain bool
}

// Open opens LDAP connection
func Open(cfg Config) (search, error) {
	if cfg.Port == 0 {
		// default LDAP port is used if it is not provided
		cfg.Port = LdapPort
	}
	if cfg.Scope < 0 || cfg.Scope > 2 {
		cfg.Scope = 2
	}
	if cfg.SizeLimit == 0 {
		cfg.SizeLimit = 50
	}
	if cfg.TimeLimit == 0 {
		cfg.TimeLimit = 10
	}

	// simpliest case when both hostname and all credentials provided, using go native LDAP library
	if cfg.Hostname != "" && cfg.BindDN != "" && cfg.BindPassword != "" {
		return &ldapConnection{Config: cfg}, nil
	}
	if cfg.Hostname == "" && runtime.GOOS == "windows" {
		return &winSpecificConnection{Config: cfg}, nil
	}

	return nil, LdapUnsupported
}

func (c *ldapConnection) do(f func(c *ldap.Conn) error) error {
	conn, err := ldap.Dial("tcp", fmt.Sprintf("%s:%d", c.Hostname, c.Port))
	if err != nil {
		return fmt.Errorf("ldap do: failed to connect: %v", err)
	}
	defer conn.Close()

	if err := conn.Bind(c.BindDN, c.BindPassword); err != nil {
		return fmt.Errorf("ldap do: initial bind for user %q failed: %v", c.BindDN, err)
	}
	return f(conn)
}

// EscapeFilter escapes search query filter
func EscapeFilter(filter string) string {
	return ldap.EscapeFilter(filter)
}

func (c *ldapConnection) Search(domain string, result interface{}, filter string) error {
	baseDN := makeDN("dc", strings.Split(domain, "."))
	res, err := newSearchResult(result)
	if err != nil {
		return fmt.Errorf("ldap.search: failed to make search result: %v", err)
	}

	search := &ldap.SearchRequest{
		BaseDN:     baseDN,
		Filter:     filter,
		Scope:      c.Scope,
		Attributes: res.tagsList,
		SizeLimit:  int(c.SizeLimit),
		TimeLimit:  int(c.TimeLimit),
	}

	var objs []*ldap.Entry
	if err = c.do(func(conn *ldap.Conn) error {
		resp, searchError := conn.Search(search)
		if searchError != nil && !strings.HasPrefix(err.Error(), "LDAP Result Code 4") {
			return fmt.Errorf("ldap.search: %v", searchError)
		}
		objs = resp.Entries
		return nil
	}); err != nil && err != LdapSizeExceeded {
		return err
	}

	for _, obj := range objs {
		item := res.NewItem()
		for _, field := range res.tagsList {
			item.Set(field, getAttr(*obj, field))
		}
		res.Add(item)
	}

	return err
}

func getAttr(e ldap.Entry, name string) string {
	for _, a := range e.Attributes {
		if a.Name != name {
			continue
		}
		if len(a.Values) == 0 {
			return ""
		}
		return a.Values[0]
	}
	if name == "DN" {
		return e.DN
	}
	return ""
}
