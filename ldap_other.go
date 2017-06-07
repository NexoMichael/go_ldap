// +build !windows

package ldap

func (c *winSpecificConnection) Search(domain string, result interface{}, filter string) error {
	panic("unsupported and should not be never called")
}
