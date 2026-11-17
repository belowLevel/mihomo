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
		Host: "beacons1.gvt3.com",
	}
	helper := C.RuleMatchHelper{}
	t.Log(ad.Match(metadata, helper))
}

func BenchmarkName(b *testing.B) {
	ad, err := common.NewAdguard("filter_1.txt", "")
	if err != nil {
		b.Fatal(err)
	}
	metadata := &C.Metadata{
		Host: "beacons1.gvt3.com",
	}
	helper := C.RuleMatchHelper{}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ad.Match(metadata, helper)
	}
}
