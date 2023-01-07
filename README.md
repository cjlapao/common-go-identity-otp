# Common Identity Framework OTP

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT) [![PR Builder](https://github.com/cjlapao/common-go-identity-otp/actions/workflows/pr.yml/badge.svg)](https://github.com/cjlapao/common-go-identity-otp/actions/workflows/pr.yml) [![CI Release](https://github.com/cjlapao/common-go-identity-otp/actions/workflows/ci.yml/badge.svg)](https://github.com/cjlapao/common-go-identity-otp/actions/workflows/ci.yml) [![CodeQL](https://github.com/cjlapao/common-go-identity-otp/actions/workflows/codeql-analysis.yml/badge.svg)](https://github.com/cjlapao/common-go-identity-otp/actions/workflows/codeql-analysis.yml)  

OTP Algorithm implementation in go to be used with the identity package

This allows to generate the HOTP and the TOTP codes that are compatible with most applications out there, the recovery is not implemented yet but is part of a further down the line roadmap.

This can be easily implemented in your backend but it does need a persistent structure
