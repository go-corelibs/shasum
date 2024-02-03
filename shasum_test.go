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
	"errors"
	"os"
	"sync"
	"testing"

	. "github.com/smartystreets/goconvey/convey"
)

const (
	gTestHash224 = "d14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f"
	gTestHash256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
	gTestHash384 = "38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b"
	gTestHash512 = "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e"
	gTestHash1   = "da39a3ee5e6b4b0d3255bfef95601890afd80709"
)

var (
	gSumTests = []struct {
		Label  string
		Type   HashType
		Expect string
	}{
		{"Brief", BriefType, gTestHash256[:BriefLength]},
		{"Sha224", Sha224Type, gTestHash224},
		{"Sha256", Sha256Type, gTestHash256},
		{"Sha384", Sha384Type, gTestHash384},
		{"Sha512", Sha512Type, gTestHash512},
	}
)

func mkFile() (path string, err error) {
	fh, _ := os.CreateTemp("", "corelibs-shasum.*")
	defer fh.Close()
	path = fh.Name()
	return
}

func Test(t *testing.T) {

	Convey("Default", t, func() {

		Convey("Hash", func() {
			m := &sync.Mutex{}
			for _, test := range gSumTests {
				Convey(test.Label, func() {
					m.Lock()
					defer m.Unlock()
					origType := DefaultType
					defer func() {
						DefaultType = origType
					}()
					shasum, err := Hash([]byte{}, test.Type)
					So(err, ShouldBeNil)
					So(shasum, ShouldEqual, test.Expect)
				})
			}
		})

		Convey("MustHash", func() {
			m := &sync.Mutex{}
			for _, test := range gSumTests {
				Convey(test.Label, func() {
					m.Lock()
					defer m.Unlock()
					So(func() {
						_ = MustHash([]byte{}, test.Type)
					}, ShouldNotPanic)
				})
			}
		})

		Convey("Sum", func() {
			m := &sync.Mutex{}
			for _, test := range gSumTests {
				Convey(test.Label, func() {
					m.Lock()
					defer m.Unlock()
					origType := DefaultType
					defer func() {
						DefaultType = origType
					}()
					DefaultType = test.Type
					shasum, err := Sum([]byte{})
					So(err, ShouldBeNil)
					So(shasum, ShouldEqual, test.Expect)
				})
			}
		})

		Convey("MustSum", func() {
			m := &sync.Mutex{}
			for _, test := range gSumTests {
				Convey(test.Label, func() {
					m.Lock()
					defer m.Unlock()
					origType := DefaultType
					defer func() {
						DefaultType = origType
					}()
					DefaultType = test.Type
					So(func() {
						_ = MustSum([]byte{})
					}, ShouldNotPanic)
				})
			}
		})

		Convey("BriefSum", func() {
			m := &sync.Mutex{}
			for _, test := range gSumTests {
				Convey(test.Label, func() {
					m.Lock()
					defer m.Unlock()
					origType := DefaultType
					defer func() {
						DefaultType = origType
					}()
					DefaultType = test.Type
					shasum, err := BriefSum([]byte{})
					So(err, ShouldBeNil)
					So(shasum, ShouldEqual, test.Expect[:BriefLength])
				})
			}
		})

		Convey("MustBriefSum", func() {
			m := &sync.Mutex{}
			for _, test := range gSumTests {
				Convey(test.Label, func() {
					m.Lock()
					defer m.Unlock()
					origType := DefaultType
					defer func() {
						DefaultType = origType
					}()
					DefaultType = test.Type
					So(func() {
						_ = MustBriefSum([]byte{})
					}, ShouldNotPanic)
				})
			}
		})

		Convey("HashFile", func() {
			path, err := mkFile()
			So(err, ShouldBeNil)
			defer os.Remove(path)
			shasum, err := HashFile(path, Sha256Type)
			So(err, ShouldBeNil)
			So(shasum, ShouldEqual, gTestHash256)
		})

		Convey("MustHashFile", func() {
			path, err := mkFile()
			So(err, ShouldBeNil)
			defer os.Remove(path)
			So(func() {
				_ = MustHashFile(path, Sha256Type)
			}, ShouldNotPanic)
		})

		Convey("File", func() {
			path, err := mkFile()
			So(err, ShouldBeNil)
			defer os.Remove(path)
			shasum, err := File(path)
			So(err, ShouldBeNil)
			So(shasum, ShouldEqual, gTestHash256)
		})

		Convey("MustFile", func() {
			path, err := mkFile()
			So(err, ShouldBeNil)
			defer os.Remove(path)
			So(func() {
				_ = MustFile(path)
			}, ShouldNotPanic)
		})

		Convey("BriefFile", func() {
			path, err := mkFile()
			So(err, ShouldBeNil)
			defer os.Remove(path)
			shasum, err := BriefFile(path)
			So(err, ShouldBeNil)
			So(shasum, ShouldEqual, gTestHash256[:BriefLength])
		})

		Convey("MustBriefFile", func() {
			path, err := mkFile()
			So(err, ShouldBeNil)
			defer os.Remove(path)
			So(func() {
				_ = MustBriefFile(path)
			}, ShouldNotPanic)
		})

	})

	Convey("Hashing", t, func() {

		Convey("Sum224", func() {
			shasum, err := Sum224([]byte{})
			So(err, ShouldBeNil)
			So(shasum, ShouldEqual, gTestHash224)
		})

		Convey("Sum256", func() {
			shasum, err := Sum256([]byte{})
			So(err, ShouldBeNil)
			So(shasum, ShouldEqual, gTestHash256)
		})

		Convey("Sum384", func() {
			shasum, err := Sum384([]byte{})
			So(err, ShouldBeNil)
			So(shasum, ShouldEqual, gTestHash384)
		})

		Convey("Sum512", func() {
			shasum, err := Sum512([]byte{})
			So(err, ShouldBeNil)
			So(shasum, ShouldEqual, gTestHash512)
		})

		Convey("MustSum224", func() {
			So(func() {
				_ = MustSum224([]byte{})
			}, ShouldNotPanic)
		})

		Convey("MustSum256", func() {
			So(func() {
				_ = MustSum256([]byte{})
			}, ShouldNotPanic)
		})

		Convey("MustSum384", func() {
			So(func() {
				_ = MustSum384([]byte{})
			}, ShouldNotPanic)
		})

		Convey("MustSum512", func() {
			So(func() {
				_ = MustSum512([]byte{})
			}, ShouldNotPanic)
		})

	})

	Convey("Unsafe", t, func() {

		Convey("Sha1Bytes", func() {
			shasum := Sha1Bytes([]byte{})
			So(shasum, ShouldEqual, [20]uint8{218, 57, 163, 238, 94, 107, 75, 13, 50, 85, 191, 239, 149, 96, 24, 144, 175, 216, 7, 9})
		})

		Convey("Sha1Sum", func() {
			shasum := Sha1Sum([]byte{})
			So(shasum, ShouldEqual, gTestHash1)
		})

	})

	Convey("Validation", t, func() {

		Convey("Valid", func() {
			So(Valid(""), ShouldBeFalse)
			So(Valid("012345678z"), ShouldBeFalse)
			So(Valid("0123456789"), ShouldBeTrue)
			So(Valid("01234567890123456789012345678901234567890123456789012345"), ShouldBeTrue)
			So(Valid("0123456789012345678901234567890123456789012345678901234567890123"), ShouldBeTrue)
			So(Valid("012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345"), ShouldBeTrue)
			So(Valid("01234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567"), ShouldBeTrue)
		})

	})

	Convey("Verification", t, func() {

		Convey("Verify", func() {
			So(Verify(gTestHash256, []byte{}), ShouldBeNil)
			So(Verify("nope", []byte{}), ShouldNotBeNil)
		})

		Convey("VerifyFile", func() {
			path, err := mkFile()
			So(err, ShouldBeNil)
			defer os.Remove(path)
			So(err, ShouldBeNil)
			So(VerifyFile(gTestHash256, path), ShouldBeNil)
			So(VerifyFile("nope", path), ShouldNotBeNil)
		})

	})

	Convey("Panic Test", t, func() {
		So(func() {
			_ = mustFn([]byte{}, func(data []byte) (shasum string, err error) {
				err = errors.New("panic")
				return
			})
		}, ShouldPanic)
	})

}
