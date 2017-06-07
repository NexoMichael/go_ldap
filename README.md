# Golang LDAP client

OS-independent LDAP client with native support for Microsoft Windows AD.

## Example

    type SearchResult struct {
        AccountName    string `ldap:"sAMAccountName"`
        DN             string `ldap:"distinguishedName"`
        SID            SID    `ldap:"objectSid"`
        DisplayName    string `ldap:"displayName"`
        ObjectCategory string `ldap:"objectCategory"`
        AccountType    string `ldap:"sAMAccountType"`
        Name           string `ldap:"name"`
    }

    func TestLdap(t *testing.T) {
        conn, err := Open(Config{
            Hostname:     "127.0.0.1",
            BindDN:       "user",
            BindPassword: "password",
            SizeLimit:    100,
            Scope:        2,
        })

        assert.Nil(t, err)

        query := "Admin"
        filter := fmt.Sprintf(`(&(anr=%s*)(|(&(sAMAccountType=805306368)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))(&(objectCategory=group)(groupType:1.2.840.113556.1.4.803:=2147483648))))`,
            EscapeFilter(query),
        )

        res := []SearchResult{}

        err = conn.Search("domain.local", &res, filter)
        fmt.Println(err)
        fmt.Printf("%+v\n", res)
    }