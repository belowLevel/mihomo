package common

import (
	"github.com/openacid/low/bitmap"
	"unsafe"

	/*"slices"*/
	"golang.org/x/exp/slices"
)

// mod from https://github.com/openacid/succinct

const prefixLabel = '\r'

type Set struct {
	leaves, labelBitmap []uint64
	labels              []byte
	ranks, selects      []int32
}

// NewSet creates a new *Set struct, from a slice of sorted strings.
func NewSet(strs []string) *Set {
	for i, v := range strs {
		strs[i] = reverseDomainSuffix(v)
	}

	slices.Sort(strs)

	unique := strs[:0]
	for _, key := range strs {
		if len(unique) == 0 || unique[len(unique)-1] != key {
			unique = append(unique, key)
		}
	}

	ss := &Set{}
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
func (ss *Set) Has(key string) bool {
	kbs := S2b(key)
	klen := len(kbs)
	nodeId, bmIdx := 0, 0
	recentMatch := false
	for i := klen - 1; i >= 0; i-- {
		c := kbs[i]
		for ; ; bmIdx++ {
			//glog.Printf("%c", c)
			if getBit(ss.labelBitmap, bmIdx) != 0 {
				// no more labels in this node
				//if c == '.' {
				//	return true
				//} else {
				//	return false
				//}
				return recentMatch
			}

			la := ss.labels[bmIdx-nodeId]
			// isPrefix := la == '\r'
			// if isPrefix {
			// 	log.Printf("%c '/r' \n", c)
			// } else {
			// 	log.Printf("%c '%c'\n", c, la)
			// }

			if c == '.' && la == prefixLabel {
				recentMatch = true
			}
			if la == c {
				break
			}
		}
		// log.Printf("%c\n", c)
		// go to next level

		nodeId = countZeros(ss.labelBitmap, ss.ranks, bmIdx+1)
		bmIdx = selectIthOne(ss.labelBitmap, ss.ranks, ss.selects, nodeId-1) + 1
	}

	match := ss.labels[bmIdx-nodeId] == prefixLabel
	if match {
		return true
	}
	return recentMatch
}

func setBit(bm *[]uint64, i int, v int) {
	for i>>6 >= len(*bm) {
		*bm = append(*bm, 0)
	}
	(*bm)[i>>6] |= uint64(v) << uint(i&63)
}

func getBit(bm []uint64, i int) uint64 {
	return bm[i>>6] & (1 << uint(i&63))
}

// init builds pre-calculated cache to speed up rank() and select()
func (ss *Set) init() {
	ss.selects, ss.ranks = bitmap.IndexSelect32R64(ss.labelBitmap)
}

// countZeros counts the number of "0" in a bitmap before the i-th bit(excluding
// the i-th bit) on behalf of rank index.
// E.g.:
//
//	countZeros("010010", 4) == 3
//	//          012345
func countZeros(bm []uint64, ranks []int32, i int) int {
	a, _ := bitmap.Rank64(bm, ranks, int32(i))
	return i - int(a)
}

// selectIthOne returns the index of the i-th "1" in a bitmap, on behalf of rank
// and select indexes.
// E.g.:
//
//	selectIthOne("010010", 1) == 4
//	//            012345
func selectIthOne(bm []uint64, ranks, selects []int32, i int) int {
	a, _ := bitmap.Select32R64(bm, selects, ranks, int32(i))
	return int(a)
}

func reverseDomainSuffix(domain string) string {
	l := len(domain)
	b := make([]byte, l+1)

	copy(b, domain)

	for i := 0; i < l/2; i++ {
		j := l - 1 - i
		b[i], b[j] = b[j], b[i]
	}

	b[l] = prefixLabel
	return B2s(b)
}

func (ss *Set) Size() int {
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

func B2s(b []byte) string {
	return unsafe.String(unsafe.SliceData(b), len(b))
}

// s2b converts string to a byte slice without memory allocation.
func S2b(s string) []byte {
	return unsafe.Slice(unsafe.StringData(s), len(s))
}
