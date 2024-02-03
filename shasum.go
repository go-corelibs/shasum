// Copyright (c) 2024  The Go-CoreLibs Authors
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

// Package shasum provides secure hash algorithm utilities
package shasum

import (
	clPath "github.com/go-corelibs/path"
)

// HashType is used to specify the DefaultType used by Sum and File
type HashType uint

const (
	// BriefType is an alias for Sha256Type
	BriefType  HashType = 10
	Sha224Type HashType = 224
	Sha256Type HashType = 256
	Sha384Type HashType = 384
	Sha512Type HashType = 512
)

var (
	DefaultType = Sha256Type
)

// HashLength is the length of a hexadecimal encoded string produced from one
// of the secure hashing functions
type HashLength uint

const (
	// BriefLength is accepted as a short-form Sha256Length
	BriefLength  HashLength = 10
	Sha224Length HashLength = 56
	Sha256Length HashLength = 64
	Sha384Length HashLength = 96
	Sha512Length HashLength = 128
)

// HashInputTypes is the generic constraint for byte slice and string things
type HashInputTypes interface {
	~[]byte | ~string
}

// Hash calculates the shasum of the given `data` and returns the hexadecimal
// encoded value
//
// BriefType is an alias of Sha256Type and if an unknown HashType is given,
// Sha256Type is used
func Hash[V HashInputTypes](data V, t HashType) (shasum string, err error) {
	switch t {
	case Sha224Type:
		shasum, err = Sum224(data)
	case Sha384Type:
		shasum, err = Sum384(data)
	case Sha512Type:
		shasum, err = Sum512(data)
	case BriefType, Sha256Type:
		fallthrough
	default:
		if shasum, err = Sum256(data); t == BriefType && len(shasum) > int(BriefLength) {
			shasum = shasum[:BriefLength]
		}
	}
	return
}

// MustHash is a convenience wrapper around Hash which panics with any error
func MustHash[V HashInputTypes](data V, t HashType) (shasum string) {
	shasum = mustFn(data, func(data V) (shasum string, err error) {
		shasum, err = Hash(data, t)
		return
	})
	return
}

// Sum is a wrapper around Hash using the DefaultType
func Sum[V HashInputTypes](data V) (shasum string, err error) {
	shasum, err = Hash(data, DefaultType)
	return
}

// MustSum is a wrapper around Sum which panics with any error
func MustSum[V HashInputTypes](data V) (shasum string) {
	shasum = mustFn(data, Sum[V])
	return
}

// BriefSum is a wrapper around Sum which returns a BriefLength `shasum`
func BriefSum[V HashInputTypes](data V) (shasum string, err error) {
	if shasum, err = Sum(data); err == nil && len(shasum) > int(BriefLength) {
		shasum = shasum[:BriefLength]
	}
	return
}

// MustBriefSum is a wrapper around BriefSum which panics with any error
func MustBriefSum[V HashInputTypes](data V) (shasum string) {
	shasum = mustFn(data, BriefSum[V])
	return
}

// HashFile is a convenience wrapper around reading the `file` data and
// returning the result of a call to Hash
func HashFile(file string, t HashType) (shasum string, err error) {
	var data []byte
	if data, err = clPath.ReadFile(file); err == nil {
		shasum, err = Hash(data, t)
	}
	return
}

// MustHashFile is a convenience wrapper around HashFile which panics with any
// error
func MustHashFile(file string, t HashType) (shasum string) {
	if data, err := clPath.ReadFile(file); err == nil {
		shasum = MustHash(data, t)
	}
	return
}

// File is a convenience wrapper around HashFile using the DefaultType
func File(file string) (shasum string, err error) {
	shasum, err = HashFile(file, DefaultType)
	return
}

// MustFile is a convenience wrapper around MustHashFile using the DefaultType
func MustFile(file string) (shasum string) {
	shasum = MustHashFile(file, DefaultType)
	return
}

// BriefFile is a wrapper around File which returns a BriefLength `shasum`
func BriefFile(file string) (shasum string, err error) {
	if shasum, err = File(file); err == nil && len(shasum) > int(BriefLength) {
		shasum = shasum[:BriefLength]
	}
	return
}

// MustBriefFile is a wrapper around File which returns a BriefLength `shasum`
func MustBriefFile(file string) (shasum string) {
	if shasum = MustFile(file); len(shasum) > int(BriefLength) {
		shasum = shasum[:BriefLength]
	}
	return
}
