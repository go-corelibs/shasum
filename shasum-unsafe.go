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
	"crypto/sha1"
	"fmt"
)

// Sha1Sum is a convenience wrapper around Sha1Bytes, returning the `shasum`
// as a hexadecimal string instead of a byte array
//
// Note: do not use SHA-1 for securing data
func Sha1Sum(data []byte) (shasum string) {
	shasum = fmt.Sprintf("%x", Sha1Bytes(data))
	return
}

// Sha1Bytes is a convenience wrapper around sha1.Sum
//
// Note: do not use SHA-1 for securing data
func Sha1Bytes(data []byte) (shasum [20]byte) {
	shasum = sha1.Sum(data)
	return
}
