package ldap

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

type SearchItem struct {
	Item  string `ldap:"itemTag"`
	Item2 string `ldap:"aaa"`
}

func TestNewSearchResult(t *testing.T) {
	_, err := newSearchResult(SearchItem{})
	assert.Equal(t, SearchResultNeedPointer, err)

	_, err = newSearchResult(&SearchItem{})
	assert.Equal(t, SearchResultBadType, err)

	_, err = newSearchResult(&[]int{})
	assert.Equal(t, SearchResultBadElement, err)

	searchResult := []SearchItem{}
	res, err := newSearchResult(&searchResult)
	assert.Nil(t, err)
	assert.NotNil(t, res)
	assert.Equal(t, map[string]string{"itemTag": "Item", "aaa": "Item2"}, res.tagFields)

	item := res.NewItem()
	assert.Equal(t, map[string]string{"itemTag": "Item", "aaa": "Item2"}, item.tagFields)
	item.Set("itemTag", "value1")
	item.Set("aaa", "value2")
	res.Add(item)

	item2 := res.NewItem()
	assert.Equal(t, map[string]string{"itemTag": "Item", "aaa": "Item2"}, item.tagFields)
	item2.Set("itemTag", "value3")
	item2.Set("aaa", "value4")
	res.Add(item2)

	assert.Equal(t, []SearchItem{{Item: "value1", Item2: "value2"}, {Item: "value3", Item2: "value4"}}, searchResult)
}
