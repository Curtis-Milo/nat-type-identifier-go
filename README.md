# nat-type-identifier-go
A Go based implementation of Network Address Transalation (NAT) type identifier based on nat-type-identifier (written by Hutchison-Technologies) and PyStun (written by gaohawk). This repository follows follows RFC 3489 https://www.ietf.org/rfc/rfc3489.txt


The return of execution will return the NAT type in use by the system running the program, the returned type will be one of the following:

```
- Blocked
- Open Internet
- Full Cone
- Symmetric UDP Firewall
- Restric NAT
- Restric Port NAT
- Symmetric NAT
```

## Features

To ensure the most reliable result, the program executes a number of tests which each determine the NAT type before a mode is selected from the list of results based on the most probable type. This is because issues might occur where occasional UDP packets fail to deliver.



## Usage

```
import (
    natType "github.com/Curtis-Milo/nat-type-identifier-go"
)

func main() {
	natType.GetDeterminedNatType(true, 10, "stun.sipgate.net")
}

```

## Installation

`go get github.com/Curtis-Milo/nat-type-identifier-go`


## Sponsored by 

This project was sponsored by www.menlolab.com
## License

```
Copyright (c) Hutchison Technologies Ltd. MIT Licensed

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
```
