package cache

import (
	"iatp/setting"
	"sync"
)

type Cache interface {
	IsWriteCache(event interface{}) interface{}
}

type CacheEvent struct {
	events []interface{}
	lock   sync.Mutex
}

func NewCacheEvent() *CacheEvent {
	return &CacheEvent{
		events: make([]interface{}, 0),
	}
}

func (cache *CacheEvent) WriteEvent(event interface{}) int {
	cache.lock.Lock()
	defer cache.lock.Unlock()

	cache.events = append(cache.events, event)
	return len(cache.events)
}

func (cache *CacheEvent) ReadAllEvent() []interface{} {
	cache.lock.Lock()
	defer cache.lock.Unlock()

	ret_events := cache.events
	cache.events = make([]interface{}, 0)

	return ret_events
}

var CacheEventMap map[interface{}]Cache

var cache_events *CacheEvent

const MAXCACHEEVENTNUMS = 4096

func init() {
	CacheEventMap = make(map[interface{}]Cache)

	cache_events = NewCacheEvent()
}

func WriteCache(event interface{}, event_type string) {
	switch event_type {
	case "event_log":
		if cache_events.WriteEvent(event) == MAXCACHEEVENTNUMS {
			setting.CacheMongo.InsertMany(cache_events.ReadAllEvent())
		}
	}
}
