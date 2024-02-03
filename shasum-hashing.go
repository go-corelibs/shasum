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
	"crypto/sha256"
	"crypto/sha512"
)

// Sum224 uses SHA-224 to hash the given `data` and return the result as a
// hexadecimal encoded string of Sha224Length
func Sum224[V HashInputTypes](data V) (shasum string, err error) {
	shasum, err = makeFn(sha256.New224(), []byte(data))
	return
}

// MustSum224 is a wrapper around Sum224 which panics with any error
func MustSum224[V HashInputTypes](data V) (shasum string) {
	shasum = mustFn(data, Sum224[V])
	return
}

// Sum256 uses SHA-256 to hash the given `data` and return the result as a
// hexadecimal encoded string of Sha256Length
func Sum256[V HashInputTypes](data V) (shasum string, err error) {
	shasum, err = makeFn(sha256.New(), []byte(data))
	return
}

// MustSum256 is a wrapper around Sum256 which panics with any error
func MustSum256[V HashInputTypes](data V) (shasum string) {
	shasum = mustFn(data, Sum256[V])
	return
}

// Sum384 uses SHA-384 to hash the given `data` and return the result as a
// hexadecimal encoded string of Sha384Length
func Sum384[V HashInputTypes](data V) (shasum string, err error) {
	shasum, err = makeFn(sha512.New384(), []byte(data))
	return
}

// MustSum384 is a wrapper around Sum384 which panics with any error
func MustSum384[V HashInputTypes](data V) (shasum string) {
	shasum = mustFn(data, Sum384[V])
	return
}

// Sum512 uses SHA-512 to hash the given `data` and return the result as a
// hexadecimal encoded string of Sha512Length
func Sum512[V HashInputTypes](data V) (shasum string, err error) {
	shasum, err = makeFn(sha512.New(), []byte(data))
	return
}

// MustSum512 is a wrapper around Sum512 which panics with any error
func MustSum512[V HashInputTypes](data V) (shasum string) {
	shasum = mustFn(data, Sum512[V])
	return
}
