# dnutil

dnutil is a library for easy handling of distinguished name.
This library is useful for creating and editing a distiguished name for use in Certificates, CRL and CSR in Golang.
With this library, you can easily and freely create [Issuer](https://datatracker.ietf.org/doc/html/rfc5280#section-4.1.2.4) and [Subject](https://datatracker.ietf.org/doc/html/rfc5280#section-4.1.2.6) based on [RFC 5280](https://datatracker.ietf.org/doc/html/rfc5280).

## Installation

```sh
go get github.com/tardevnull/dnutil
```

## Example
```go

```
## Usage
### type DN []RDN
DN represents an ASN.1 DistinguishedName object.
```
//Distinguished Name Example
C=JP,O=example,OU=Ext,OU=Dev+OU=Sales,CN=ex+E=ex@example.com

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
var d = DN{
	RDN{AttributeTypeAndValue{Type: CountryName, Value: AttributeValue{Encoding: PrintableString, String: "JP"}}},
	RDN{AttributeTypeAndValue{Type: OrganizationName, Value: AttributeValue{Encoding: UTF8String, String: "example"}}},
	RDN{AttributeTypeAndValue{Type: OrganizationalUnit, Value: AttributeValue{Encoding: UTF8String, String: "Ext"}}},
	RDN{
		AttributeTypeAndValue{Type: OrganizationalUnit, Value: AttributeValue{Encoding: UTF8String, String: "Dev"}},
		AttributeTypeAndValue{Type: OrganizationalUnit, Value: AttributeValue{Encoding: UTF8String, String: "Sales"}},
	},
	RDN{
		AttributeTypeAndValue{Type: CommonName, Value: AttributeValue{Encoding: UTF8String, String: "ex"}},
		AttributeTypeAndValue{Type: ElectronicMailAddress, Value: AttributeValue{Encoding: IA5String, String: "ex@example.com"}}},
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
dn := DN{RDN{AttributeTypeAndValue{Type: CommonName, Value: AttributeValue{Encoding: UTF8String, String: "cn1"}}},}
b, err := MarshalDN(dn)
```

### func ParseDERDN(dnBytes []byte) (dn DN, err error)
ParseDERDn parses a distinguished name, ASN.1 DER form and returns DN.
```
//CN=abc (UTF8String)
b := []byte{0x30, 0x0e, 0x31, 0x0c, 0x30, 0x0a, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0c, 0x03, 0x61, 0x62, 0x63}
dn, err := ParseDERDn(b)
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