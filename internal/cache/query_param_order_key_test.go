package cache

import (
	"net/http/httptest"
	"testing"
)

// F3400: repeated query parameters are order-significant, so the cache key
// must keep their relative order while still ignoring the order of
// differently named parameters.
func TestGenerateKeyRepeatedParamOrder(t *testing.T) {
	key := func(q string) string { return GenerateKey(httptest.NewRequest("GET", "http://h/p?"+q, nil), nil) }

	if key("a=1&a=2") == key("a=2&a=1") {
		t.Error("repeated parameter in different order shares a key")
	}
	if key("ids[]=1&ids[]=2&x=9") == key("ids[]=2&ids[]=1&x=9") {
		t.Error("list parameter order ignored")
	}
	if key("a=1&a") == key("a&a=1") {
		t.Error("valueless repeat order ignored")
	}
	// Differently named parameters still permute freely.
	if key("b=2&a=1") != key("a=1&b=2") {
		t.Error("distinct names must share a key")
	}
	if key("a=1&a=2&b=3") != key("b=3&a=1&a=2") {
		t.Error("moving b must not change the key while a keeps its order")
	}
	if key("a=1") == key("a=2") {
		t.Error("distinct values share a key")
	}
	// More than stackParamsCap parameters takes the heap path.
	long1, long2 := "", ""
	for i := 0; i < 20; i++ {
		long1 += "p=" + string(rune('a'+i)) + "&"
		long2 = "p=" + string(rune('a'+i)) + "&" + long2
	}
	if key(long1) == key(long2) {
		t.Error("overflow path ignored repeated parameter order")
	}
	if key("z=1&"+long1+"y=2") != key(long1+"y=2&z=1") {
		t.Error("overflow path must still ignore order of distinct names")
	}
}
