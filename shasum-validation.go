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

// Valid checks if the `hash` given is a valid HashLength string
// that passes a call to Validate
func Valid(hash string) (valid bool) {
	switch HashLength(len(hash)) {
	case BriefLength:
		return Validate(hash, BriefLength)
	case Sha224Length:
		return Validate(hash, Sha224Length)
	case Sha256Length:
		return Validate(hash, Sha256Length)
	case Sha384Length:
		return Validate(hash, Sha384Length)
	case Sha512Length:
		return Validate(hash, Sha512Length)
	}
	return
}

// Validate returns true if the given `hash` is exactly the HashLength
// required and contains only the digits 0-9 and the lower-case letters a-f
func Validate(hash string, size HashLength) (valid bool) {
	if valid = len(hash) == int(size); valid {
		for _, char := range hash {
			switch char {
			case '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f':
			default:
				valid = false
				return
			}
		}
	}
	return
}
