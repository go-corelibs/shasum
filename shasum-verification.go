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
	clPath "github.com/go-corelibs/path"
)

// Verify compares the given `hash` matches the exact Sum result derived
// from the given `data`
func Verify(hash string, data []byte) (err error) {
	var shasum string
	if shasum, err = Sum(data); err == nil && shasum != hash {
		err = ErrVerifyFailed
	}
	return
}

// VerifyFile uses Verify to validate the given file's integrity
func VerifyFile(hash, file string) (err error) {
	var data []byte
	if data, err = clPath.ReadFile(file); err == nil {
		err = Verify(hash, data)
	}
	return
}
