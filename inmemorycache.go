package dnsgrab

import (
	"container/list"

	"github.com/getlantern/dnsgrab/common"
)

// inMemoryCache is a size bounded in-memory cache
type inMemoryCache struct {
	size      int
	namesByIP map[uint32]*list.Element
	ipsByName map[string]uint32
	ll        *list.List
	sequence  uint32
}

func NewInMemoryCache(size int) Cache {
	return &inMemoryCache{
		size:      size,
		namesByIP: make(map[uint32]*list.Element, size),
		ipsByName: make(map[string]uint32, size),
		ll:        list.New(),
		sequence:  common.MinIP,
	}
}

func (cache *inMemoryCache) NameByIP(ip []byte) (name string, found bool) {
	e, found := cache.namesByIP[common.IPToInt(ip)]
	if !found {
		return "", false
	}
	return e.Value.(string), true
}

func (cache *inMemoryCache) IPByName(name string) (ip []byte, found bool) {
	_ip, found := cache.ipsByName[name]
	if !found {
		return nil, false
	}
	return common.IntToIP(_ip), true
}

func (cache *inMemoryCache) Add(name string, ip []byte) {
	ipInt := common.IPToInt(ip)
	// insert to front of LRU list
	e := cache.ll.PushFront(name)
	cache.namesByIP[ipInt] = e
	cache.ipsByName[name] = ipInt

	// remove oldest from LRU list if necessary
	if len(cache.namesByIP) > cache.size {
		oldest := cache.ll.Back()
		oldestName := oldest.Value.(string)
		cache.ll.Remove(oldest)
		oldestIP := cache.ipsByName[oldestName]
		delete(cache.namesByIP, oldestIP)
		delete(cache.ipsByName, oldestName)
	}
}

func (cache *inMemoryCache) MarkFresh(name string, ip []byte) {
	e := cache.namesByIP[common.IPToInt(ip)]
	// move to front of LRU list
	cache.ll.MoveToFront(e)
}

func (cache *inMemoryCache) NextSequence() uint32 {
	// advance sequence
	next := cache.sequence
	cache.sequence++
	if cache.sequence > common.MaxIP {
		// wrap IP to stay within allowed range
		cache.sequence = common.MinIP
	}
	return next
}
