[![Go Reference](https://pkg.go.dev/badge/github.com/tardevnull/dnutil.svg)](https://pkg.go.dev/github.com/tardevnull/dnutil)[![Go](https://github.com/tardevnull/dnutil/actions/workflows/go.yml/badge.svg)](https://github.com/tardevnull/dnutil/actions/workflows/go.yml)
# dnutil

dnutil is a library for easy handling of distinguished name.
This library is useful for creating and editing a distinguished name for use in Certificates, CRL and CSR in Golang.
With this library, you can easily and freely create [Issuer](https://datatracker.ietf.org/doc/html/rfc5280#section-4.1.2.4) and [Subject](https://datatracker.ietf.org/doc/html/rfc5280#section-4.1.2.6) based on [RFC 5280](https://datatracker.ietf.org/doc/html/rfc5280).

## Installation

```sh
go get github.com/tardevnull/dnutil@latest
```

## Example
```go
package main

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"log"
	"os"

	"github.com/tardevnull/dnutil"
)

func main() {

	//CN=ex+0.9.2342.19200300.100.1.1=userid_0001+E=ex@example.com,OU=Dev+OU=Sales,OU=Ext,O=example,C=JP
	d := dnutil.DN{
		dnutil.RDN{dnutil.AttributeTypeAndValue{Type: dnutil.CountryName, Value: dnutil.AttributeValue{Encoding: dnutil.PrintableString, Value: "JP"}}},
		dnutil.RDN{dnutil.AttributeTypeAndValue{Type: dnutil.OrganizationName, Value: dnutil.AttributeValue{Encoding: dnutil.UTF8String, Value: "example"}}},
		dnutil.RDN{dnutil.AttributeTypeAndValue{Type: dnutil.OrganizationalUnit, Value: dnutil.AttributeValue{Encoding: dnutil.UTF8String, Value: "Ext"}}},
		dnutil.RDN{
			dnutil.AttributeTypeAndValue{Type: dnutil.OrganizationalUnit, Value: dnutil.AttributeValue{Encoding: dnutil.UTF8String, Value: "Dev"}},
			dnutil.AttributeTypeAndValue{Type: dnutil.OrganizationalUnit, Value: dnutil.AttributeValue{Encoding: dnutil.UTF8String, Value: "Sales"}},
		},
		dnutil.RDN{
			dnutil.AttributeTypeAndValue{Type: dnutil.CommonName, Value: dnutil.AttributeValue{Encoding: dnutil.UTF8String, Value: "ex"}},
			dnutil.AttributeTypeAndValue{Type: dnutil.Generic, Oid: "0.9.2342.19200300.100.1.1", Value: dnutil.AttributeValue{Encoding: dnutil.UTF8String, Value: "userid_0001"}},
			dnutil.AttributeTypeAndValue{Type: dnutil.ElectronicMailAddress, Value: dnutil.AttributeValue{Encoding: dnutil.IA5String, Value: "ex@example.com"}}},
	}

	subjectBytes, err := dnutil.MarshalDN(d)
	if err != nil {
		log.Fatalf("ERROR:%v\n", err)
	}
	fmt.Println(hex.EncodeToString(subjectBytes))

	dn, err := dnutil.ParseDERDN(subjectBytes)
	if err != nil {
		log.Fatalf("ERROR:%v\n", err)
	}
	fmt.Println(dn)

	//Create CertificateRequest
	privateKey, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		log.Fatalf("ERROR:%v\n", err)
	}
	var publicKey crypto.PublicKey
	publicKey = privateKey.Public()

	if err != nil {
		log.Fatalf("ERROR:%v\n", err)
	}

	template := &x509.CertificateRequest{
		PublicKeyAlgorithm: x509.RSA,
		PublicKey:          publicKey,
		SignatureAlgorithm: x509.SHA256WithRSA,
		RawSubject:         subjectBytes,
	}

	csr, err := x509.CreateCertificateRequest(rand.Reader, template, privateKey)
	err = pem.Encode(os.Stdout, &pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csr})
	if err != nil {
		log.Fatalf("ERROR:%v\n", err)
	}

}
```
[example](https://go.dev/play/p/theWxZMtALk)


## Usage
### type DN []RDN
DN represents an ASN.1 DistinguishedName object.
```
//Distinguished Name Example
CN=ex+0.9.2342.19200300.100.1.1=userid_0001+E=ex@example.com,OU=Dev+OU=Sales,OU=Ext,O=example,C=JP

C: PrintableString
O: UTF8String
OU=Ext: UTF8String
OU=Dev: UTF8String
OU=Sales: UTF8String
CN: UTF8String
UID(0.9.2342.19200300.100.1.1): UTF8String
EMAIL(ElectronicMailAddress): IA5String
```
you can write it as DN struct:
```
var d = dnutil.DN{
	dnutil.RDN{dnutil.AttributeTypeAndValue{Type: dnutil.CountryName, Value: dnutil.AttributeValue{Encoding: dnutil.PrintableString, Value: "JP"}}},
	dnutil.RDN{dnutil.AttributeTypeAndValue{Type: dnutil.OrganizationName, Value: dnutil.AttributeValue{Encoding: dnutil.UTF8String, Value: "example"}}},
	dnutil.RDN{dnutil.AttributeTypeAndValue{Type: dnutil.OrganizationalUnit, Value: dnutil.AttributeValue{Encoding: dnutil.UTF8String, Value: "Ext"}}},
	dnutil.RDN{
		dnutil.AttributeTypeAndValue{Type: dnutil.OrganizationalUnit, Value: dnutil.AttributeValue{Encoding: dnutil.UTF8String, Value: "Dev"}},
		dnutil.AttributeTypeAndValue{Type: dnutil.OrganizationalUnit, Value: dnutil.AttributeValue{Encoding: dnutil.UTF8String, Value: "Sales"}},},
	dnutil.RDN{
		dnutil.AttributeTypeAndValue{Type: dnutil.CommonName, Value: dnutil.AttributeValue{Encoding: dnutil.UTF8String, Value: "ex"}},
		dnutil.AttributeTypeAndValue{Type: dnutil.Generic, Oid: "0.9.2342.19200300.100.1.1", Value: dnutil.AttributeValue{Encoding: dnutil.UTF8String, Value: "userid_0001"}},
		dnutil.AttributeTypeAndValue{Type: dnutil.ElectronicMailAddress, Value: dnutil.AttributeValue{Encoding: dnutil.IA5String, Value: "ex@example.com"}}},
}
```
#### Note:
- RDN of the DN should have at least one AttributeTypeAndValue element.
- AttributeValue currently supports the following ASN.1 string encodings:
```
  PrintableString 
  UTF8String
  IA5String
```
- AttributeType currently supports the following AttributeTypes:
```
  CountryName (2.5.4.6)
  OrganizationName (2.5.4.10)
  OrganizationalUnit (2.5.4.11)
  DnQualifier (2.5.4.46)
  StateOrProvinceName (2.5.4.8)
  CommonName (2.5.4.3)
  SerialNumber (2.5.4.5)
  LocalityName (2.5.4.7)
  Title (2.5.4.12)
  Surname (2.5.4.4)
  GivenName (2.5.4.42)
  Initials (2.5.4.43)
  Pseudonym (2.5.4.65)
  GenerationQualifier (2.5.4.44)
  ElectronicMailAddress (1.2.840.113549.1.9.1)
  DomainComponent (0.9.2342.19200300.100.1.25)
  Generic (Any OBJECT IDENTIFIER)
```
- Any object identifier can be specified by setting Generic to Type and object identifier to Oid.
- If Type is Generic, Oid must be specified.
- Currently, the following combinations of OBJECT IDENTIFIER for AttributeType and Encoding for AttributeValue are supported:
```
  2.5.4.6 (CountryName) : PrintableString
  2.5.4.10 (OrganizationName) : PrintableString or UTF8String
  2.5.4.11 (OrganizationalUnit) : PrintableString or UTF8String
  2.5.4.46 (DnQualifier) : PrintableString
  2.5.4.8 (StateOrProvinceName) : PrintableString or UTF8String
  2.5.4.3 (CommonName) : PrintableString or UTF8String
  2.5.4.5 (SerialNumber) : PrintableString
  2.5.4.7 (LocalityName) : PrintableString or UTF8String
  2.5.4.12 (Title) : PrintableString or UTF8String
  2.5.4.4 (Surname) : PrintableString or UTF8String
  2.5.4.42 (GivenName) : PrintableString or UTF8String
  2.5.4.43 (Initials) : PrintableString or UTF8String
  2.5.4.65 (Pseudonym) : PrintableString or UTF8String
  2.5.4.44 (GenerationQualifier) : PrintableString or UTF8String
  1.2.840.113549.1.9.1 (ElectronicMailAddress) : IA5String
  0.9.2342.19200300.100.1.25 (DomainComponent) : IA5String
  Any OBJECT IDENTIFIER other than those already listed (Generic) : PrintableString or UTF8String or IA5String 
```
- If Type is Generic and Oid is a known AttributeType object identifier(CountryName(="2.5.4.6"), OrganizationName(="2.5.4.10"), etc.), the combination follows the one already enumerated.
ex: If Type: Generic, Oid: "2.5.4.6"(=CountryName), then only PrintableString is allowed. 

### func MarshalDN(dn DN) (dnBytes []byte, err error)
MarshalDN converts a DN to distinguished name (DN), ASN.1 DER form.
```
dn := dnutil.DN{dnutil.RDN{dnutil.AttributeTypeAndValue{Type: dnutil.CommonName, Value: dnutil.AttributeValue{Encoding: dnutil.UTF8String, Value: "cn1"}}},}
b, err := dnutil.MarshalDN(d)
```

### func ParseDERDN(dnBytes []byte) (dn DN, err error)
ParseDERDn parses a distinguished name, ASN.1 DER form and returns DN.
```
//CN=abc (UTF8String)
b := []byte{0x30, 0x0e, 0x31, 0x0c, 0x30, 0x0a, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0c, 0x03, 0x61, 0x62, 0x63}
dn, err := dnutil.ParseDERDN(b)
```
#### Note:
- AttributeValue of the relative distinguished name currently supported are following ASN.1 string encodings:
```
PrintableString
UTF8String
IA5String
```
- AttributeTypeAndValue of the relative distinguished name currently supported are following combinations of OBJECT IDENTIFIER of AttributeType and Encoding of the AttributeValue:
```
2.5.4.6  : PrintableString
2.5.4.10 : PrintableString or UTF8String
2.5.4.11 : PrintableString or UTF8String
2.5.4.46 : PrintableString
2.5.4.8 : PrintableString or UTF8String
2.5.4.3 : PrintableString or UTF8String
2.5.4.5  : PrintableString
2.5.4.7 : PrintableString or UTF8String
2.5.4.12 : PrintableString or UTF8String
2.5.4.4 : PrintableString or UTF8String
2.5.4.42 : PrintableString or UTF8String
2.5.4.43 : PrintableString or UTF8String
2.5.4.65 : PrintableString or UTF8String
2.5.4.44 : PrintableString or UTF8String
1.2.840.113549.1.9.1 : IA5String
0.9.2342.19200300.100.1.25 : IA5String
The other OBJECT IDENTIFIER : PrintableString or UTF8String or IA5String
```

### func (d DN) ToRFC4514FormatString() string
ToRFC4514FormatString returns an RFC4514 Format string of the DN.
```
d := dnutil.DN{
	dnutil.RDN{dnutil.AttributeTypeAndValue{Type: dnutil.CountryName, Value: dnutil.AttributeValue{Encoding: dnutil.PrintableString, Value: "JP"}}},
	dnutil.RDN{dnutil.AttributeTypeAndValue{Type: dnutil.OrganizationName, Value: dnutil.AttributeValue{Encoding: dnutil.UTF8String, Value: "example Co., Ltd"}}},
	dnutil.RDN{dnutil.AttributeTypeAndValue{Type: dnutil.OrganizationalUnit, Value: dnutil.AttributeValue{Encoding: dnutil.UTF8String, Value: "A,B;"}}},
	dnutil.RDN{
		dnutil.AttributeTypeAndValue{Type: dnutil.OrganizationalUnit, Value: dnutil.AttributeValue{Encoding: dnutil.UTF8String, Value: "#Dev"}},
		dnutil.AttributeTypeAndValue{Type: dnutil.OrganizationalUnit, Value: dnutil.AttributeValue{Encoding: dnutil.UTF8String, Value: " Sales"}},
	},
	dnutil.RDN{
		dnutil.AttributeTypeAndValue{Type: dnutil.CommonName, Value: dnutil.AttributeValue{Encoding: dnutil.UTF8String, Value: "ex"}},
		dnutil.AttributeTypeAndValue{Type: dnutil.Generic, Oid: "0.9.2342.19200300.100.1.1", Value: dnutil.AttributeValue{Encoding: dnutil.UTF8String, Value: "userid_0001"}},
		dnutil.AttributeTypeAndValue{Type: dnutil.ElectronicMailAddress, Value: dnutil.AttributeValue{Encoding: dnutil.IA5String, Value: "ex@example.com"}}},
}
```

```
RFC4514 section2 Format: CN=ex+0.9.2342.19200300.100.1.1=userid_0001+EMAIL=ex@example.com,OU=\#Dev+OU=\ Sales,OU=A\,B\;,O=example Co.\, Ltd,C=JP
```

## License
[BSD 3-Clause](https://github.com/tardevnull/dnutil/blob/main/LICENSE)
