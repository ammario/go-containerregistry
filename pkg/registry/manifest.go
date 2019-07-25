// Copyright 2018 Google LLC All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//    http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package registry

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path"
	"strings"
	"sync"
)

type manifest struct {
	contentType string
	blob        []byte
}

type manifests struct {
	// manifests are structured as objects named "<repo>/<tag>" and "<repo>/<digest>"
	// which contains a JSON-encoded manifest.
	// An empty object simply named <repo> is created to indicate repo existence.
	manifests objectStore
	lock      sync.Mutex
}

func isManifest(req *http.Request) bool {
	elems := strings.Split(req.URL.Path, "/")
	elems = elems[1:]
	if len(elems) < 4 {
		return false
	}
	return elems[len(elems)-2] == "manifests"
}

// https://github.com/opencontainers/distribution-spec/blob/master/spec.md#pulling-an-image-manifest
// https://github.com/opencontainers/distribution-spec/blob/master/spec.md#pushing-an-image
func (m *manifests) handle(resp http.ResponseWriter, req *http.Request) *regError {
	elem := strings.Split(req.URL.Path, "/")
	elem = elem[1:]
	target := elem[len(elem)-1]
	repo := strings.Join(elem[1:len(elem)-2], "/")

	if req.Method == "GET" || req.Method == "HEAD" {
		ok, err := objectExists(m.manifests, repo)
		if !ok {
			if err != nil {
				return &regError{
					Status:  http.StatusInternalServerError,
					Code:    "MANIFEST_INVALID",
					Message: err.Error(),
				}
			}
			return &regError{
				Status:  http.StatusNotFound,
				Code:    "NAME_UNKNOWN",
				Message: "Unknown name",
			}
		}

		f, err := m.manifests.open(path.Join(repo, target), 0)
		if err != nil {
			return &regError{
				Status:  http.StatusNotFound,
				Code:    "MANIFEST_UNKNOWN",
				Message: err.Error(),
			}
		}
		defer f.Close()

		var m manifest

		err = json.NewDecoder(f).Decode(&m)
		if err != nil {
			return &regError{
				Status:  http.StatusInternalServerError,
				Code:    "ERROR",
				Message: err.Error(),
			}
		}

		rd := sha256.Sum256(m.blob)
		d := "sha256:" + hex.EncodeToString(rd[:])
		resp.Header().Set("Docker-Content-Digest", d)
		resp.Header().Set("Content-Type", m.contentType)
		resp.Header().Set("Content-Length", fmt.Sprint(len(m.blob)))
		resp.WriteHeader(http.StatusOK)
		if req.Method == "GET" {
			_, _ = io.Copy(resp, bytes.NewReader(m.blob))
		}
		return nil
	}

	if req.Method == "PUT" {
		// Create manifest existence indicator.
		err := create(m.manifests, repo)
		if err != nil {
			return &regError{
				Status:  http.StatusInternalServerError,
				Code:    "ERROR",
				Message: err.Error(),
			}
		}
		b := &bytes.Buffer{}
		_, _ = io.Copy(b, req.Body)
		rd := sha256.Sum256(b.Bytes())
		digest := "sha256:" + hex.EncodeToString(rd[:])
		mf := manifest{
			blob:        b.Bytes(),
			contentType: req.Header.Get("Content-Type"),
		}

		// See https://docs.docker.com/engine/reference/commandline/pull/#pull-an-image-by-digest-immutable-identifier.
		targetFile, err := m.manifests.open(path.Join(repo, target), os.O_CREATE)
		if err != nil {
			return &regError{
				Status:  http.StatusInternalServerError,
				Code:    "ERROR",
				Message: err.Error(),
			}
		}
		defer targetFile.Close()

		digestFile, err := m.manifests.open(path.Join(repo, digest), os.O_CREATE)
		if err != nil {
			return &regError{
				Status:  http.StatusInternalServerError,
				Code:    "ERROR",
				Message: err.Error(),
			}
		}
		defer digestFile.Close()

		err = json.NewEncoder(io.MultiWriter(digestFile, targetFile)).Encode(mf)
		if err != nil {
			return &regError{
				Status:  http.StatusInternalServerError,
				Code:    "ERROR",
				Message: err.Error(),
			}
		}

		resp.Header().Set("Docker-Content-Digest", digest)
		resp.WriteHeader(http.StatusCreated)
		return nil
	}
	return &regError{
		Status:  http.StatusBadRequest,
		Code:    "METHOD_UNKNOWN",
		Message: "We don't understand your method + url",
	}
}
