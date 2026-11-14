package rule

import (
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/rules/common"
	"testing"
)

func TestName(t *testing.T) {
	ad, err := common.NewAdguard("filter_1.txt", "")
	if err != nil {
		t.Fatal(err)
	}
	metadata := &C.Metadata{
		Host: "omniture.walmart.com",
	}
	helper := C.RuleMatchHelper{}
	t.Log(ad.Match(metadata, helper))
}
