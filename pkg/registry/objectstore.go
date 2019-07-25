package registry

import (
	"errors"
	"io"
	"os"
)

var errNotFound = errors.New("not found")

// objectStore represents generic file-system like storage.
type objectStore interface {
	// open returns a handle to the object.
	// Each goroutine must only have a single handle to each object at a time.
	// flags supports os.O_TRUNCATE and os.O_CREATE.
	open(key string, flags int) (io.ReadWriteCloser, error)
	delete(key string) error
}

// objectExists checks if an object exists in the store.
func objectExists(s objectStore, key string) (bool, error) {
	fi, err := s.open(key, 0)
	if err == errNotFound {
		return false, nil
	} else if err != nil {
		return false, err
	}
	return true, fi.Close()
}

// create attempts to create an object in the store.
// It does not error if the item already exists.
func create(s objectStore, key string) error {
	f, err := s.open(key, os.O_CREATE)
	if err != nil {
		return err
	}
	return f.Close()
}
