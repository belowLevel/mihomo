package common

import (
	"bufio"
	C "github.com/metacubex/mihomo/constant"
	"os"
	"path"
	"strings"
	"unicode"
)

type DomainTxt struct {
	Base
	set      *Set
	payload  string
	filePath string
	adapter  string
}

func (dt *DomainTxt) RuleType() C.RuleType {
	return C.DomainTxt
}

func (dt *DomainTxt) Match(metadata *C.Metadata, helper C.RuleMatchHelper) (bool, string) {
	domain := metadata.RuleHost()

	if dt.set == nil {
		return false, dt.adapter
	}
	return dt.set.Has(domain), dt.adapter
}

func (dt *DomainTxt) Adapter() string {
	return dt.adapter
}

func (dt *DomainTxt) Payload() string {
	return dt.payload
}

func NewDomainTxt(payload string, adapter string) (*DomainTxt, error) {
	dt := &DomainTxt{
		Base:    Base{},
		set:     nil,
		payload: payload,
		adapter: adapter,
	}

	dt.filePath = path.Join(C.Path.HomeDir(), payload)

	var strs []string
	if _, err := os.Stat(dt.filePath); err != nil {
		return nil, err
	}

	f, err := os.OpenFile(dt.filePath, os.O_RDONLY, os.ModePerm)
	if err != nil {
		return nil, err
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
		strs = append(strs, line)
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	if len(strs) == 0 {
		return dt, nil
	}
	dt.set = NewSet(strs)

	return dt, nil
}

var _ C.Rule = (*DomainTxt)(nil)
