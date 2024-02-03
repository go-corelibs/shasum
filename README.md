[![godoc](https://img.shields.io/badge/godoc-reference-blue.svg)](https://pkg.go.dev/github.com/go-corelibs/shasum)
[![codecov](https://codecov.io/gh/go-corelibs/shasum/graph/badge.svg?token=s9dBE4sci9)](https://codecov.io/gh/go-corelibs/shasum)
[![Go Report Card](https://goreportcard.com/badge/github.com/go-corelibs/shasum)](https://goreportcard.com/report/github.com/go-corelibs/shasum)

# shasum - secure hash algorithm utilities

A collection of utilities for working with secure hashes.

# Installation

``` shell
> go get github.com/go-corelibs/shasum@latest
```

# Examples

## Hash, Sum, BriefSum

``` go
func main() {
    shasum, err := shasum.Hash([]byte{}, shasum.Sha256Type)
    // err == nil
    // shasum == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    shasum, err = shasum.Sum([]byte{})
    // err == nil
    // shasum == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    shasum, err = shasum.BriefSum([]byte{})
    // err == nil
    // shasum == "e3b0c44298"
}
```

# Go-CoreLibs

[Go-CoreLibs] is a repository of shared code between the [Go-Curses] and
[Go-Enjin] projects.

# License

```
Copyright 2024 The Go-CoreLibs Authors

Licensed under the Apache License, Version 2.0 (the "License");
you may not use file except in compliance with the License.
You may obtain a copy of the license at

 http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
```

[Go-CoreLibs]: https://github.com/go-corelibs
[Go-Curses]: https://github.com/go-curses
[Go-Enjin]: https://github.com/go-enjin
