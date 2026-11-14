package common

import (
	"errors"
	"github.com/metacubex/mihomo/component/mmdb"
	C "github.com/metacubex/mihomo/constant"
	"os"
	"path"
	"path/filepath"
	"slices"
	"strings"
	"sync"
)

type DomainRecord struct {
	Base
	payload    string
	filePath   string
	conditions []string
	operator   string
	lock       sync.Mutex
	adapter    string
}

func (dr *DomainRecord) RuleType() C.RuleType {
	return C.DomainRecord
}

func (dr *DomainRecord) Match(metadata *C.Metadata, helper C.RuleMatchHelper) (bool, string) {
	domain := metadata.RuleHost()
	if domain == "" {
		return false, dr.adapter
	}
	if helper.ResolveIP != nil {
		helper.ResolveIP()
	}

	ip := metadata.DstIP
	if !ip.IsValid() {
		return false, ""
	}
	codes := mmdb.IPInstance().LookupCode(ip.AsSlice())
	metadata.DstGeoIP = codes
	dr.matchISO(codes, domain)
	return false, dr.adapter
}

func (dr *DomainRecord) Adapter() string {
	return dr.adapter
}

func (dr *DomainRecord) Payload() string {
	return dr.payload
}

func NewDomainRecord(payload string, adapter string, params []string) (*DomainRecord, error) {
	operator := ""
	var codes []string
	if len(params) > 0 {
		operator = params[0]
		codes = params[1:]
	}
	if operator != "" {
		if (operator != "or" && operator != "and") || len(codes) == 0 {
			return nil, errors.New("The params are not valid")
		}
	}
	dr := &DomainRecord{
		Base:       Base{},
		payload:    payload,
		adapter:    adapter,
		operator:   operator,
		conditions: codes,
	}

	for i, v := range dr.conditions {
		dr.conditions[i] = strings.ToLower(v)
	}
	dr.filePath = path.Join(C.Path.HomeDir(), payload)
	dr.filePath = filepath.Clean(dr.filePath)
	return dr, nil
}

func (dr *DomainRecord) matchISO(codes []string, host string) bool {
	if len(codes) == 0 {
		return false
	}
	var match bool
	switch dr.operator {
	case "and":
		match = true
		for _, cond := range dr.conditions {
			if cond[0] == '!' {
				cond = cond[1:]
				match = slices.Contains(codes, cond)
				match = !match
			} else {
				match = slices.Contains(codes, cond)
			}
			if !match {
				return false
			}
		}
	case "or":
		for _, cond := range dr.conditions {
			if cond[0] == '!' {
				cond = cond[1:]
				match = slices.Contains(codes, cond)
				match = !match
			} else {
				match = slices.Contains(codes, cond)
			}
			if match {
				break
			}
		}
	default:
		match = true
	}

	if match {
		dr.save(host)
		return true
	}
	return false
}

func (dr *DomainRecord) save(domain string) {
	dr.lock.Lock()
	defer dr.lock.Unlock()
	f, err := os.OpenFile(dr.filePath, os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0644)
	if err != nil {
		return
	}
	defer func() {
		_ = f.Close()
	}()
	_, _ = f.WriteString(domain + "\n")
}

var _ C.Rule = (*DomainRecord)(nil)
