[![Go Reference](https://pkg.go.dev/badge/github.com/tardevnull/dnutil.svg)](https://pkg.go.dev/github.com/tardevnull/dnutil)[![Go](https://github.com/tardevnull/dnutil/actions/workflows/go.yml/badge.svg)](https://github.com/tardevnull/dnutil/actions/workflows/go.yml)
# dnutil

dnutil is a library for easy handling of distinguished name.
This library is useful for creating and editing a distinguished name for use in Certificates, CRL and CSR in Golang.
With this library, you can easily and freely create [Issuer](https://datatracker.ietf.org/doc/html/rfc5280#section-4.1.2.4) and [Subject](https://datatracker.ietf.org/doc/html/rfc5280#section-4.1.2.6) based on [RFC 5280](https://datatracker.ietf.org/doc/html/rfc5280).

## Installation

```sh
go get github.com/tardevnull/dnutil
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

	//CN=ex+E=ex@example.com,OU=Dev+OU=Sales,OU=Ext,O=example,C=JP
	d := dnutil.DN{
		dnutil.RDN{dnutil.AttributeTypeAndValue{Type: dnutil.CountryName, Value: dnutil.AttributeValue{Encoding: dnutil.PrintableString, String: "JP"}}},
		dnutil.RDN{dnutil.AttributeTypeAndValue{Type: dnutil.OrganizationName, Value: dnutil.AttributeValue{Encoding: dnutil.UTF8String, String: "example"}}},
		dnutil.RDN{dnutil.AttributeTypeAndValue{Type: dnutil.OrganizationalUnit, Value: dnutil.AttributeValue{Encoding: dnutil.UTF8String, String: "Ext"}}},
		dnutil.RDN{
			dnutil.AttributeTypeAndValue{Type: dnutil.OrganizationalUnit, Value: dnutil.AttributeValue{Encoding: dnutil.UTF8String, String: "Dev"}},
			dnutil.AttributeTypeAndValue{Type: dnutil.OrganizationalUnit, Value: dnutil.AttributeValue{Encoding: dnutil.UTF8String, String: "Sales"}},
		},
		dnutil.RDN{
			dnutil.AttributeTypeAndValue{Type: dnutil.CommonName, Value: dnutil.AttributeValue{Encoding: dnutil.UTF8String, String: "ex"}},
			dnutil.AttributeTypeAndValue{Type: dnutil.ElectronicMailAddress, Value: dnutil.AttributeValue{Encoding: dnutil.IA5String, String: "ex@example.com"}}},
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
[example](https://go.dev/play/p/NHCZ_4nnXMT)

## Usage
### type DN []RDN
DN represents an ASN.1 DistinguishedName object.
```
//Distinguished Name Example
CN=ex+E=ex@example.com,OU=Dev+OU=Sales,OU=Ext,O=example,C=JP

C: PrintableString
O: UTF8String
OU=Ext: UTF8String
OU=Dev: UTF8String
OU=Sales: UTF8String
CN:UTF8String
E(ElectronicMailAddress):IA5String
```
you can write it as DN struct:
```
var d = dnutil.DN{
	dnutil.RDN{dnutil.AttributeTypeAndValue{Type: dnutil.CountryName, Value: dnutil.AttributeValue{Encoding: dnutil.PrintableString, String: "JP"}}},
	dnutil.RDN{dnutil.AttributeTypeAndValue{Type: dnutil.OrganizationName, Value: dnutil.AttributeValue{Encoding: dnutil.UTF8String, String: "example"}}},
	dnutil.RDN{dnutil.AttributeTypeAndValue{Type: dnutil.OrganizationalUnit, Value: dnutil.AttributeValue{Encoding: dnutil.UTF8String, String: "Ext"}}},
	dnutil.RDN{
		dnutil.AttributeTypeAndValue{Type: dnutil.OrganizationalUnit, Value: dnutil.AttributeValue{Encoding: dnutil.UTF8String, String: "Dev"}},
		dnutil.AttributeTypeAndValue{Type: dnutil.OrganizationalUnit, Value: dnutil.AttributeValue{Encoding: dnutil.UTF8String, String: "Sales"}},},
	dnutil.RDN{
		dnutil.AttributeTypeAndValue{Type: dnutil.CommonName, Value: dnutil.AttributeValue{Encoding: dnutil.UTF8String, String: "ex"}},
		dnutil.AttributeTypeAndValue{Type: dnutil.ElectronicMailAddress, Value: dnutil.AttributeValue{Encoding: dnutil.IA5String, String: "ex@example.com"}}},
}
```
#### Note:
- RDN of the DN should have at least one AttributeTypeAndValue element.

- AttributeValue of the DN currently supported are following ASN.1 string encodings:
```
  PrintableString 
  UTF8String
  IA5String
```
- AttributeType of the DN currently supported are following AttributeTypes:
```
  CountryName
  OrganizationName
  OrganizationalUnit
  DnQualifier
  StateOrProvinceName
  CommonName
  SerialNumber
  LocalityName
  Title
  Surname
  GivenName
  Initials
  Pseudonym
  GenerationQualifier
  ElectronicMailAddress
  DomainComponent
```
- AttributeTypeAndValue of the DN currently supported are following combinations of AttributeType and Encoding of the AttributeValue:
```
  CountryName : PrintableString
  OrganizationName : PrintableString or UTF8String
  OrganizationalUnit : PrintableString or UTF8String
  DnQualifier : PrintableString
  StateOrProvinceName : PrintableString or UTF8String
  CommonName : PrintableString or UTF8String
  SerialNumber : PrintableString
  LocalityName : PrintableString or UTF8String
  Title : PrintableString or UTF8String
  Surname : PrintableString or UTF8String
  GivenName : PrintableString or UTF8String
  Initials : PrintableString or UTF8String
  Pseudonym : PrintableString or UTF8String
  GenerationQualifier : PrintableString or UTF8String
  ElectronicMailAddress : IA5String
  DomainComponent : IA5String
```

### func MarshalDN(dn DN) (dnBytes []byte, err error)
MarshalDN converts a DN to distinguished name (DN), ASN.1 DER form.
```
dn := dnutil.DN{dnutil.RDN{dnutil.AttributeTypeAndValue{Type: dnutil.CommonName, Value: dnutil.AttributeValue{Encoding: dnutil.UTF8String, String: "cn1"}}},}
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
- AttributeValue of the distinguished name currently supported are following ASN.1 string encodings:
```
PrintableString
UTF8String
IA5String
```
- AttributeType of the distinguished name currently supported are following OBJECT IDENTIFIER of AttributeTypes:
```
2.5.4.6  CountryName
2.5.4.10  OrganizationName
2.5.4.11  OrganizationalUnit
2.5.4.46  DnQualifier
2.5.4.8  StateOrProvinceName
2.5.4.3  CommonName
2.5.4.5  SerialNumber
2.5.4.7  LocalityName
2.5.4.12  Title
2.5.4.4  Surname
2.5.4.42  GivenName
2.5.4.43  Initials
2.5.4.65  Pseudonym
2.5.4.44  GenerationQualifier
1.2.840.113549.1.9.1  ElectronicMailAddress
0.9.2342.19200300.100.1.25  DomainComponent
```
- AttributeTypeAndValue of the distinguished name currently supported are following combinations of OBJECT IDENTIFIER of AttributeType and Encoding of the AttributeValue:
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
```

## License
[BSD 3-Clause](https://github.com/tardevnull/dnutil/blob/main/LICENSE)
