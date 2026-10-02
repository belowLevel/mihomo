package common

import (
	"bufio"
	"errors"
	"github.com/metacubex/mihomo/component/mmdb"
	C "github.com/metacubex/mihomo/constant"
	"os"
	"path"
	"slices"
	"strings"
	"sync"
	"unicode"
)

type DomainRecord struct {
	Base
	set        *Set
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
	if dr.set == nil {
		return false, dr.adapter
	}
	domain := metadata.RuleHost()
	if domain == "" {
		return false, dr.adapter
	}
	if dr.set.Has(domain) {
		return true, dr.adapter
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
	if dr.matchISO(codes, domain) {
		return true, dr.adapter
	}
	return false, dr.adapter
}

func (dr *DomainRecord) Adapter() string {
	return dr.adapter
}

func (dr *DomainRecord) Payload() string {
	return dr.payload
}

func NewDomainRecord(payload string, adapter string, params []string) (*DomainRecord, error) {
	if len(params) < 2 {
		return nil, errors.New("The params are not valid")
	}
	operator := params[0]
	if operator != "or" && operator != "and" {
		return nil, errors.New("The params are not valid")
	}

	dr := &DomainRecord{
		Base:       Base{},
		set:        nil,
		payload:    payload,
		adapter:    adapter,
		operator:   operator,
		conditions: params[1:],
	}

	for i, v := range dr.conditions {
		dr.conditions[i] = strings.ToLower(v)
	}

	dr.filePath = path.Join(C.Path.HomeDir(), payload)
	err := dr.newSet()
	if err != nil {
		return nil, err
	}
	return dr, nil
}

func (dr *DomainRecord) newSet() error {
	var strs []string
	if _, err := os.Stat(dr.filePath); err != nil {
		return err
	}

	f, err := os.OpenFile(dr.filePath, os.O_RDONLY, os.ModePerm)
	if err != nil {
		return err
	}
	defer func() {
		_ = f.Close()
	}()
	scanner := bufio.NewScanner(f)
	var count = 0
	for scanner.Scan() {
		line := scanner.Text()
		line = strings.TrimSpace(line)
		line = strings.TrimFunc(line, func(r rune) bool {
			return !unicode.IsGraphic(r)
		})
		if line == "" {
			continue
		}
		count++
		strs = append(strs, line)
	}
	if err := scanner.Err(); err != nil {
		return err
	}
	if len(strs) == 0 {
		strs = append(strs, "placeholder.placeholder")
	}
	dr.set = NewSet(strs)
	return nil
}

func (dr *DomainRecord) matchISO(codes []string, host string) bool {
	if len(codes) == 0 {
		return false
	}
	var match bool
	if dr.operator == "and" {
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
	} else if dr.operator == "or" {
		match = false
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
	} else {
		return false
	}

	if match {
		go func() {
			dr.save(host)
		}()
		return true
	}
	return false
}

func (dr *DomainRecord) save(domain string) {
	dr.lock.Lock()
	defer dr.lock.Unlock()
	var strs = make([]string, 0, 1000)
	var seen = make(map[string]bool, 1000)
	if _, err := os.Stat(dr.filePath); err == nil {
		f, err := os.OpenFile(dr.filePath, os.O_RDONLY, os.ModePerm)
		if err != nil {
			return
		}
		defer func() {
			_ = f.Close()
		}()
		scanner := bufio.NewScanner(f)
		for scanner.Scan() {
			line := scanner.Text()
			line = strings.TrimSpace(line)
			line = strings.TrimFunc(line, func(r rune) bool {
				return !unicode.IsGraphic(r)
			})
			if line == "" {
				continue
			}
			if seen[line] {
				continue
			}
			strs = append(strs, line)
		}
		if err := scanner.Err(); err != nil {
			return
		}

	}
	if seen[domain] {
		return
	}
	strs = append(strs, domain)
	f, err := os.OpenFile(dr.filePath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, os.ModePerm)
	if err != nil {
		return
	}
	defer func() {
		_ = f.Close()
	}()
	for _, v := range strs {
		_, _ = f.WriteString(v + "\n")
	}
	_ = dr.newSet()
}

var _ C.Rule = (*DomainRecord)(nil)
