// Copyright (c) 2024  The Go-Enjin Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package shasum

import (
	"fmt"
	"hash"
)

// makeFn calls h.Write and returns the hexadecimal encoded h.Sum result
func makeFn(h hash.Hash, data []byte) (shasum string, err error) {
	if _, err = h.Write(data); err == nil {
		shasum = fmt.Sprintf("%x", h.Sum(nil))
	}
	return
}

// mustFn is a generic function for performing a hashing operation and
// panicking with any error
func mustFn[V HashInputTypes](data V, fn func(data V) (shasum string, err error)) (shasum string) {
	var err error
	if shasum, err = fn(data); err != nil {
		panic(err)
	}
	return
}
