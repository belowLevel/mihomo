package rule_test

import (
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/hub/executor"
	"github.com/metacubex/mihomo/rules/common"
	"log"
	"path/filepath"
	"testing"
)

func getADomainTxtRule() *common.DomainTxt {
	configFile := filepath.Join(C.Path.HomeDir(), C.Path.Config())
	cfg, err := executor.ParseWithPath(configFile)
	if err != nil {
		log.Fatal(err)
	}
	var domainTxtRule *common.DomainTxt
	for _, v := range cfg.Rules {
		ruleWrapper, ok := v.(C.RuleWrapper)
		if ok {
			rule := ruleWrapper.Unwrap()
			domainTxtRule, ok = rule.(*common.DomainTxt)
			if ok {
				break
			}
		}
	}
	if domainTxtRule == nil {
		log.Fatal("no domainTxtRule")
	}
	return domainTxtRule
}

func getAGeoSiteRule() *common.GEOSITE {
	configFile := filepath.Join(C.Path.HomeDir(), C.Path.Config())
	cfg, err := executor.ParseWithPath(configFile)
	if err != nil {
		log.Fatal(err)
	}
	var geoSite *common.GEOSITE
	for _, v := range cfg.Rules {
		ruleWrapper, ok := v.(C.RuleWrapper)
		if ok {
			rule := ruleWrapper.Unwrap()
			geoSite, ok = rule.(*common.GEOSITE)
			if ok {
				break
			}
		}
	}
	if geoSite == nil {
		log.Fatal("no geoSite")
	}
	return geoSite
}
func TestDomainTxt(t *testing.T) {
	domainTxtRule := getADomainTxtRule()
	metadata := &C.Metadata{
		Host: "arms-retcode.aliyuncs.com",
	}
	helper := C.RuleMatchHelper{}
	match, adapter := domainTxtRule.Match(metadata, helper)
	t.Log(match, adapter)
}

func TestGeoSite(t *testing.T) {
	geoSite := getAGeoSiteRule()
	metadata := &C.Metadata{
		Host: "arms-retcode.aliyuncs.com",
	}
	helper := C.RuleMatchHelper{}
	match, adapter := geoSite.Match(metadata, helper)
	t.Log(match, adapter)
}

func BenchmarkDomainTxt(b *testing.B) {
	domainTxtRule := getADomainTxtRule()
	metadata := &C.Metadata{
		Host: "arms-retcode.aliyuncs.com",
	}
	helper := C.RuleMatchHelper{}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = domainTxtRule.Match(metadata, helper)
	}
	//BenchmarkDomainTxt-16            4257847               283.5 ns/op             0
	//B/op          0 allocs/op
	//PASS

	//BenchmarkDomainTxt-16            4293736               277.4 ns/op             0
	//B/op          0 allocs/op
	//PASS

	//BenchmarkDomainTxt-16            39631  44               281.7 ns/op             0
	//B/op          0 allocs/op
	//PASS
}

func BenchmarkGeoSite(b *testing.B) {
	geoSiteRule := getAGeoSiteRule()
	metadata := &C.Metadata{
		Host: "arms-retcode.aliyuncs.com",
	}
	helper := C.RuleMatchHelper{}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = geoSiteRule.Match(metadata, helper)
	}
	//BenchmarkGeoSite-16      2786655               429.5 ns/op            40 B/op
	//2 allocs/op
	//PASS

	//BenchmarkGeoSite-16      2812710               428.3 ns/op            40 B/op
	//2 allocs/op
	//PASS
}
