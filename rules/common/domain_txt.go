package common

import (
	"bufio"
	"github.com/metacubex/fswatch"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/log"
	"os"
	"path"
	"path/filepath"
	"strings"
	"sync"
	"unicode"
)

var (
	domainTxtMap  = make(map[string]*DomainTxt)
	domainTxtLock sync.Mutex
)

type DomainTxt struct {
	Base
	set         *Set
	payload     string
	filePath    string
	adapter     string
	watcher     *fswatch.Watcher
	access      sync.RWMutex
	dnsStrategy string
}

func (dt *DomainTxt) RuleType() C.RuleType {
	return C.DomainTxt
}

func (dt *DomainTxt) Match(metadata *C.Metadata, helper C.RuleMatchHelper) (bool, string) {
	adaper := dt.adapter
	if metadata.DNSMode == 53 {
		adaper = dt.dnsStrategy
	}
	domain := metadata.RuleHost()
	set := dt.set
	if set == nil {
		return false, adaper
	}
	return set.Has(domain), adaper
}

func (dt *DomainTxt) Adapter() string {
	return dt.adapter
}

func (dt *DomainTxt) Payload() string {
	return dt.payload
}

func (dt *DomainTxt) reloadFile() error {
	var strs []string
	if _, err := os.Stat(dt.filePath); err != nil {
		return err
	}

	f, err := os.OpenFile(dt.filePath, os.O_RDONLY, os.ModePerm)
	if err != nil {
		return err
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
		return err
	}
	if len(strs) > 0 {
		dt.access.Lock()
		dt.set = NewSet(strs)
		dt.access.Unlock()
		log.Errorln("reloading done %s , %d lines, set Size %.3fMB", dt.filePath, len(strs), float64(dt.set.Size())/(1024*1024))
	} else {
		dt.access.Lock()
		dt.set = nil
		dt.access.Unlock()
		log.Errorln("reloading done %s , %d lines, set is now nil", dt.filePath, len(strs))
	}
	return nil
}

func NewDomainTxt(payload string, action string) (*DomainTxt, error) {
	domainTxtLock.Lock()
	defer domainTxtLock.Unlock()
	dnsStrategy := ""
	adapter := ""
	if action == "fake-ip" || action == "real-ip" {
		dnsStrategy = action
	} else {
		adapter = action
	}
	domainTxt, ok := domainTxtMap[payload]
	if ok {
		if dnsStrategy != "" {
			domainTxt.dnsStrategy = dnsStrategy
		}
		if adapter != "" {
			domainTxt.adapter = adapter
		}
		return domainTxt, nil
	}
	dt := &DomainTxt{
		Base:        Base{},
		set:         nil,
		payload:     payload,
		adapter:     adapter,
		dnsStrategy: dnsStrategy,
	}
	domainTxtMap[payload] = dt

	dt.filePath = path.Join(C.Path.HomeDir(), payload)
	dt.filePath = filepath.Clean(dt.filePath)
	err := dt.reloadFile()
	if err != nil {
		return nil, err
	}

	watcher, err := fswatch.NewWatcher(fswatch.Options{
		Path: []string{dt.filePath},
		Callback: func(path string) {
			uErr := dt.reloadFile()
			if uErr != nil {
				log.Errorln("%s", uErr)
			}
		},
	})
	if err != nil {
		return nil, err
	}
	dt.watcher = watcher
	err = dt.watcher.Start()
	log.Errorln("started new watcher for %s updates", dt.filePath)
	if err != nil {
		return nil, err
	}
	return dt, nil
}

var _ C.Rule = (*DomainTxt)(nil)
