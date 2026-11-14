package common

import (
	"bufio"
	"github.com/metacubex/fswatch"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/log"
	"github.com/openacid/low/bitmap"
	"golang.org/x/exp/slices"
	"os"
	"path"
	"path/filepath"
	"strings"
	"sync"
)

var (
	adguardMap  = make(map[string]*Adguard)
	adguardLock sync.Mutex
)

type Adguard struct {
	Base
	set         *adguardSet
	payload     string
	filePath    string
	adapter     string
	watcher     *fswatch.Watcher
	access      sync.RWMutex
	dnsStrategy string
	domainCount int
}

func (dt *Adguard) RuleType() C.RuleType {
	return C.ADGUARD
}

func (dt *Adguard) Match(metadata *C.Metadata, helper C.RuleMatchHelper) (bool, string) {
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

func (dt *Adguard) Adapter() string {
	return dt.adapter
}

func (dt *Adguard) Payload() string {
	return dt.payload
}

func (dt *Adguard) reloadFile() error {
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
		line := strings.TrimSpace(scanner.Text())
		whitelist := false

		if strings.HasPrefix(line, "@@||") {
			whitelist = true
			line = strings.TrimPrefix(line, "@@")
		}

		if !strings.HasPrefix(line, "||") {
			continue
		}

		domain := strings.TrimSuffix(line, "|")
		domain = strings.TrimSuffix(
			strings.TrimPrefix(domain, "||"), "^",
		)
		if domain == "" ||
			strings.ContainsAny(domain, "/:*?[]$") {
			continue
		}

		if whitelist {
			domain = "(" + domain
		} else {
			domain = ")" + domain
		}
		strs = append(strs, domain)
	}
	if err := scanner.Err(); err != nil {
		return err
	}
	if len(strs) > 0 {
		dt.access.Lock()
		dt.set = NewAdguardSet(strs)
		dt.domainCount = len(strs)
		dt.access.Unlock()
		log.Errorln("reloading done %s , %d lines, set Size %.3fMB", dt.filePath, dt.domainCount, float64(dt.set.Size())/(1024*1024))
	} else {
		dt.access.Lock()
		dt.set = nil
		dt.domainCount = 0
		dt.access.Unlock()
		log.Errorln("reloading done %s , %d lines, set is now nil", dt.filePath, dt.domainCount)
	}
	return nil
}

func NewAdguard(payload string, action string) (*Adguard, error) {
	adguardLock.Lock()
	defer adguardLock.Unlock()
	dnsStrategy := ""
	adapter := ""
	if action == "fake-ip" || action == "real-ip" || action == "null-ip" {
		dnsStrategy = action
	} else {
		adapter = action
	}
	adguard, ok := adguardMap[payload]
	if ok {
		if dnsStrategy != "" {
			adguard.dnsStrategy = dnsStrategy
		}
		if adapter != "" {
			adguard.adapter = adapter
		}
		log.Errorln("%s , %d lines, set Size %.3fMB", adguard.filePath, adguard.domainCount, float64(adguard.set.Size())/(1024*1024))
		return adguard, nil
	}
	dt := &Adguard{
		Base:        Base{},
		set:         nil,
		payload:     payload,
		adapter:     adapter,
		dnsStrategy: dnsStrategy,
	}
	adguardMap[payload] = dt

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

var _ C.Rule = (*Adguard)(nil)

type adguardSet struct {
	leaves, labelBitmap []uint64
	labels              []byte
	ranks, selects      []int32
}

// NewSet creates a new *Set struct, from a slice of sorted strings.
func NewAdguardSet(strs []string) *adguardSet {
	for i, v := range strs {
		strs[i] = reverseAdguardDomainSuffix(v)
	}

	slices.Sort(strs)

	unique := strs[:0]
	for _, key := range strs {
		if len(unique) == 0 || unique[len(unique)-1] != key {
			unique = append(unique, key)
		}
	}

	ss := &adguardSet{}
	lIdx := 0

	type qElt struct{ s, e, col int }

	queue := []qElt{{0, len(unique), 0}}

	for i := 0; i < len(queue); i++ {
		elt := queue[i]

		if elt.col == len(unique[elt.s]) {
			// a leaf node
			elt.s++
			setBit(&ss.leaves, i, 1)
		}

		for j := elt.s; j < elt.e; {

			frm := j

			for ; j < elt.e && unique[j][elt.col] == unique[frm][elt.col]; j++ {
			}

			queue = append(queue, qElt{frm, j, elt.col + 1})
			ss.labels = append(ss.labels, unique[frm][elt.col])
			setBit(&ss.labelBitmap, lIdx, 0)
			lIdx++
		}

		setBit(&ss.labelBitmap, lIdx, 1)
		lIdx++
	}

	ss.init()
	return ss
}

// Has query for a key and return whether it presents in the Set.
func (ss *adguardSet) Has(key string) bool {
	kbs := S2b(key)
	klen := len(kbs)
	nodeId, bmIdx := 0, 0
	recentMatch := false
	recentNoMatch := false
	for i := klen - 1; i >= 0; i-- {
		c := kbs[i]
		for ; ; bmIdx++ {
			//glog.Printf("%c", c)
			if getBit(ss.labelBitmap, bmIdx) != 0 {
				if recentNoMatch {
					return false
				}
				return recentMatch
			}

			la := ss.labels[bmIdx-nodeId]

			if c == '.' {
				if la == '(' {
					//return false
					recentNoMatch = true
				}
				if la == ')' {
					//return true
					recentMatch = true
				}
			}

			if la == c {
				break
			}
		}
		nodeId = countZeros(ss.labelBitmap, ss.ranks, bmIdx+1)
		bmIdx = selectIthOne(ss.labelBitmap, ss.ranks, ss.selects, nodeId-1) + 1
	}

	v := ss.labels[bmIdx-nodeId]
	if v == '(' {
		return false
	}
	if v == ')' {
		return true
	}
	if recentNoMatch {
		return false
	}
	return recentMatch
}

func (ss *adguardSet) init() {
	ss.selects, ss.ranks = bitmap.IndexSelect32R64(ss.labelBitmap)
}

func (ss *adguardSet) Size() int {
	if ss == nil {
		return 0
	}
	const structHeaderSize = 120

	leavesSize := cap(ss.leaves) * 8
	labelBitmapSize := cap(ss.labelBitmap) * 8
	labelsSize := cap(ss.labels) * 1
	ranksSize := cap(ss.ranks) * 4
	selectsSize := cap(ss.selects) * 4

	return structHeaderSize + leavesSize + labelBitmapSize + labelsSize + ranksSize + selectsSize
}

func reverseAdguardDomainSuffix(domain string) string {
	l := len(domain)
	b := make([]byte, l)

	copy(b, domain)

	for i := 0; i < l/2; i++ {
		j := l - 1 - i
		b[i], b[j] = b[j], b[i]
	}
	return B2s(b)
}
