package registry

import (
	"bytes"
	"io"
	"os"
	"sync"
)

type memObject struct {
	mu  sync.Mutex
	buf []byte
}

type memObjectHandle struct {
	buf *[]byte
	pos int
	mu  *sync.Mutex
}

func (m *memObjectHandle) Read(b []byte) (int, error) {
	// m.pos += len(b)
}

func (m *memObjectHandle) Close() error {
	m.mu.Unlock()
	return nil
}

func (m *memObject) open(truncate bool) io.ReadWriteCloser {
	m.mu.Lock()
	if truncate {
		m.buf.Reset()
	}
	return &memObjectHandle{
		// We want to duplicate the buffer so the read position is isolated to the handle.
		Buffer: bytes.NewBuffer(m.buf.Bytes()),
		mu:     &m.mu,
	}
}

// memStore implements objectStore in memory.
type memStore struct {
	mu sync.Mutex
	m  map[string]*memObject
}

func newMemStore() *memStore {
	return &memStore{m: make(map[string]*memObject)}
}

func (ms *memStore) open(key string, flags int) (io.ReadWriteCloser, error) {
	ms.mu.Lock()
	obj, ok := ms.m[key]
	switch {
	case !ok && flags&os.O_CREATE > 0:
		obj = &memObject{buf: bytes.Buffer{}}
		ms.m[key] = obj
	case !ok:
		ms.mu.Unlock()
		return nil, errNotFound
	}

	ms.mu.Unlock()
	h := obj.open((flags & os.O_TRUNC) > 0)
	return h, nil
}

func (ms *memStore) delete(key string) error {
	ms.mu.Lock()
	defer ms.mu.Unlock()

	_, ok := ms.m[key]
	if !ok {
		return errNotFound
	}
	delete(ms.m, key)
	return nil
}
