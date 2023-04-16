//Package dnutil implements a library for easy handling of distinguished name.
/*
dnutil is a library for easy handling of distinguished name.

*/
package dnutil

import (
	"encoding/asn1"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"unicode/utf8"
)

// AttributeType represents a Name of ASN.1 Attribute Type object.
// https://datatracker.ietf.org/doc/html/rfc5280#section-4.1.2.4
type AttributeType int

type innerAttributeTypeAndValue struct {
	//AttributeType
	Type asn1.ObjectIdentifier
	//AttributeValue
	Value asn1.RawValue
}

type innerRDNSET []innerAttributeTypeAndValue

type innerDN []innerRDNSET

// AttributeValue represents an ASN.1 AttributeValue object.
// https://datatracker.ietf.org/doc/html/rfc5280#section-4.1.2.4
type AttributeValue struct {
	Encoding Encoding
	Value    string
}

// AttributeTypeAndValue represents an ASN.1 AttributeTypeAndValue object.
// AttributeType currently supports the following AttributeTypes:
//
//	CountryName (2.5.4.6)
//	OrganizationName (2.5.4.10)
//	OrganizationalUnit (2.5.4.11)
//	DnQualifier (2.5.4.46)
//	StateOrProvinceName (2.5.4.8)
//	CommonName (2.5.4.3)
//	SerialNumber (2.5.4.5)
//	LocalityName (2.5.4.7)
//	Title (2.5.4.12)
//	Surname (2.5.4.4)
//	GivenName (2.5.4.42)
//	Initials (2.5.4.43)
//	Pseudonym (2.5.4.65)
//	GenerationQualifier (2.5.4.44)
//	ElectronicMailAddress (1.2.840.113549.1.9.1)
//	DomainComponent (0.9.2342.19200300.100.1.25)
//	Generic (Any OBJECT IDENTIFIER)
//
// Any object identifier can be specified by setting Generic to Type and object identifier to Oid.
// If Type is Generic, Oid must be specified.
//
// Currently, the following combinations of OBJECT IDENTIFIER for AttributeType
// and Encoding for AttributeValue are supported:
//
//	CountryName (2.5.4.6) : PrintableString
//	OrganizationName (2.5.4.10) : PrintableString or UTF8String
//	OrganizationalUnit (2.5.4.11) : PrintableString or UTF8String
//	DnQualifier (2.5.4.46) : PrintableString
//	StateOrProvinceName (2.5.4.8) : PrintableString or UTF8String
//	CommonName (2.5.4.3) : PrintableString or UTF8String
//	SerialNumber (2.5.4.5) : PrintableString
//	LocalityName (2.5.4.7) : PrintableString or UTF8String
//	Title (2.5.4.12) : PrintableString or UTF8String
//	Surname (2.5.4.4) : PrintableString or UTF8String
//	GivenName (2.5.4.42) : PrintableString or UTF8String
//	Initials (2.5.4.43) : PrintableString or UTF8String
//	Pseudonym (2.5.4.65) : PrintableString or UTF8String
//	GenerationQualifier (2.5.4.44) : PrintableString or UTF8String
//	ElectronicMailAddress (1.2.840.113549.1.9.1) : IA5String
//	DomainComponent (0.9.2342.19200300.100.1.25) : IA5String
//	Generic (Any OBJECT IDENTIFIER other than those already listed) : PrintableString or UTF8String or IA5String
//
// https://datatracker.ietf.org/doc/html/rfc5280#section-4.1.2.4
type AttributeTypeAndValue struct {
	//AttributeType
	Type AttributeType
	//AttributeValue
	Value AttributeValue
	//If Type is Generic, Oid must be specified
	Oid string
}

// RDN represents an ASN.1 RelativeDistinguishedName object.
// https://datatracker.ietf.org/doc/html/rfc5280#section-4.1.2.4
type RDN []AttributeTypeAndValue

// DN represents an ASN.1 DistinguishedName object.
// https://datatracker.ietf.org/doc/html/rfc5280#section-4.1.2.4
type DN []RDN

// Attribute Type Name
const (
	CountryName AttributeType = iota + 1
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
	Generic
)

var oidTable = make(map[AttributeType]asn1.ObjectIdentifier)
var attributeTypeTable = make(map[string]AttributeType)

func init() {
	oidTable[CountryName] = []int{2, 5, 4, 6}
	oidTable[OrganizationName] = []int{2, 5, 4, 10}
	oidTable[OrganizationalUnit] = []int{2, 5, 4, 11}
	oidTable[DnQualifier] = []int{2, 5, 4, 46}
	oidTable[StateOrProvinceName] = []int{2, 5, 4, 8}
	oidTable[CommonName] = []int{2, 5, 4, 3}
	oidTable[SerialNumber] = []int{2, 5, 4, 5}
	oidTable[LocalityName] = []int{2, 5, 4, 7}
	oidTable[Title] = []int{2, 5, 4, 12}
	oidTable[Surname] = []int{2, 5, 4, 4}
	oidTable[GivenName] = []int{2, 5, 4, 42}
	oidTable[Initials] = []int{2, 5, 4, 43}
	oidTable[Pseudonym] = []int{2, 5, 4, 65}
	oidTable[GenerationQualifier] = []int{2, 5, 4, 44}
	oidTable[ElectronicMailAddress] = []int{1, 2, 840, 113549, 1, 9, 1}
	oidTable[DomainComponent] = []int{0, 9, 2342, 19200300, 100, 1, 25}

	attributeTypeTable[asn1.ObjectIdentifier{2, 5, 4, 6}.String()] = CountryName
	attributeTypeTable[asn1.ObjectIdentifier{2, 5, 4, 10}.String()] = OrganizationName
	attributeTypeTable[asn1.ObjectIdentifier{2, 5, 4, 11}.String()] = OrganizationalUnit
	attributeTypeTable[asn1.ObjectIdentifier{2, 5, 4, 46}.String()] = DnQualifier
	attributeTypeTable[asn1.ObjectIdentifier{2, 5, 4, 8}.String()] = StateOrProvinceName
	attributeTypeTable[asn1.ObjectIdentifier{2, 5, 4, 3}.String()] = CommonName
	attributeTypeTable[asn1.ObjectIdentifier{2, 5, 4, 5}.String()] = SerialNumber
	attributeTypeTable[asn1.ObjectIdentifier{2, 5, 4, 7}.String()] = LocalityName
	attributeTypeTable[asn1.ObjectIdentifier{2, 5, 4, 12}.String()] = Title
	attributeTypeTable[asn1.ObjectIdentifier{2, 5, 4, 4}.String()] = Surname
	attributeTypeTable[asn1.ObjectIdentifier{2, 5, 4, 42}.String()] = GivenName
	attributeTypeTable[asn1.ObjectIdentifier{2, 5, 4, 43}.String()] = Initials
	attributeTypeTable[asn1.ObjectIdentifier{2, 5, 4, 65}.String()] = Pseudonym
	attributeTypeTable[asn1.ObjectIdentifier{2, 5, 4, 44}.String()] = GenerationQualifier
	attributeTypeTable[asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 1}.String()] = ElectronicMailAddress
	attributeTypeTable[asn1.ObjectIdentifier{0, 9, 2342, 19200300, 100, 1, 25}.String()] = DomainComponent
}

func (a AttributeType) String() string {
	switch a {
	case CountryName:
		return "CountryName"
	case OrganizationName:
		return "OrganizationName"
	case OrganizationalUnit:
		return "OrganizationUnit"
	case DnQualifier:
		return "DnQualifier"
	case StateOrProvinceName:
		return "StateOrProvinceName"
	case CommonName:
		return "CommonName"
	case SerialNumber:
		return "SerialNumber"
	case LocalityName:
		return "LocalityName"
	case Title:
		return "Title"
	case Surname:
		return "Surname"
	case GivenName:
		return "GivenName"
	case Initials:
		return "Initials"
	case Pseudonym:
		return "Pseudonym"
	case GenerationQualifier:
		return "GenerationQualifier"
	case ElectronicMailAddress:
		return "ElectronicMailAddress"
	case DomainComponent:
		return "DomainComponent"
	case Generic:
		return "Generic"
	default:
		return "UnKnown"
	}
}

// String returns a string representation of this DN.
// All string representations of RDN in the DN are concatenated with ",".
func (d DN) String() string {
	if d.CountRDN() == 0 {
		return ""
	}
	out := d
	var rdns []string
	for _, rdn := range out {
		rdns = append(rdns, rdn.String())
	}
	return strings.Join(rdns, ",")
}

// ToRFC4514FormatString returns an RFC4514 Format string of this DN.
func (d DN) ToRFC4514FormatString() string {
	//https://www.rfc-editor.org/rfc/rfc4514#section-2.1
	if d.CountRDN() == 0 {
		//If the RDNSequence is an empty sequence, the result is the empty or zero-length string.
		return ""
	}

	//the output consists of the string encodings of each RelativeDistinguishedName
	//in the RDNSequence (according to Section 2.2),
	//starting with the last element of the sequence and moving backwards toward the first.
	out := d.ReverseDnOrder()

	var rdns []string
	for _, rdn := range out {
		rdns = append(rdns, rdn.ToRFC4514FormatString())
	}
	//The encodings of adjoining RelativeDistinguishedNames are separated by a comma (',' U+002C) character.
	return strings.Join(rdns, ",")
}

// ReverseDnOrder returns a new reverse order DN.
func (d DN) ReverseDnOrder() DN {
	l := d.CountRDN()
	revDn := DN{}
	for i := l - 1; i >= 0; i-- {
		revDn = append(revDn, d[i])
	}
	return revDn
}

// String returns a string representation of this RDN.
// All string representations of AttributeTypeAndValues in the RDN are concatenated with "+".
func (r RDN) String() string {
	var atvs []string
	for _, atv := range r {
		atvs = append(atvs, atv.String())
	}
	return strings.Join(atvs, "+")
}

// ToRFC4514FormatString returns an RFC4514 Format string of this RDN.
func (r RDN) ToRFC4514FormatString() string {
	//https://www.rfc-editor.org/rfc/rfc4514#section-2.2
	var atvs []string
	for _, atv := range r {
		//the output consists of the string encodings of
		//each AttributeTypeAndValue (according to Section 2.3), in any order.
		atvs = append(atvs, atv.ToRFC4514FormatString())
	}
	//Where there is a multi-valued RDN, the outputs from adjoining AttributeTypeAndValues are separated
	//by a plus sign ('+' U+002B) character.
	return strings.Join(atvs, "+")
}

// String returns a string representation of this AttributeTypeAndValue.
// The attribute type is uppercase, and the attribute type and value are concatenated by "=".
func (atv AttributeTypeAndValue) String() string {
	return strings.ToUpper(atv.toShortName()) + "=" + atv.Value.String()
}

func (a AttributeTypeAndValue) toShortName() string {
	//https://www.rfc-editor.org/rfc/rfc4514#section-2.3
	//If the AttributeType is defined to have a short name (descriptor)
	//[RFC4512] and that short name is known to be registered [REGISTRY]
	//[RFC4520] as identifying the AttributeType, that short name, a
	//<descr>, is used.  Otherwise the AttributeType is encoded as the
	//dotted-decimal encoding, a <numericoid>, of its OBJECT IDENTIFIER.
	//	The <descr> and <numericoid> are defined in [RFC4512].

	//ShortNames are from [REGISTRY]
	//https://www.iana.org/assignments/ldap-parameters/ldap-parameters.xhtml

	//https://www.rfc-editor.org/rfc/rfc4512#section-1.4
	//   Short names, also known as descriptors, are used as more readable
	//   aliases for object identifiers.  Short names are case insensitive and
	//   conform to the ABNF:
	//
	//      descr = keystring

	var ret = toDefinedShortName(a.Type)
	if ret == "Generic" {
		o, err := convertToObjectIdentifier(a.Oid)
		if err != nil {
			//Oid format error
			return "UnKnown"
		}

		a, err := ReferAttributeTypeName(o)
		if err != nil {
			//dotted-decimal encoding, a <numericoid>
			return o.String()
		}
		//short name is known
		return toDefinedShortName(a)
	}

	//Type is Not Defined Type
	if ret == "UnKnown" {
		return "UnKnown"
	}

	return ret
}

func toDefinedShortName(a AttributeType) string {
	switch a {
	case CountryName:
		return "c"
	case OrganizationName:
		return "o"
	case OrganizationalUnit:
		return "ou"
	case DnQualifier:
		return "dnQualifier"
	case StateOrProvinceName:
		return "st"
	case CommonName:
		return "cn"
	case SerialNumber:
		return "serialNumber"
	case LocalityName:
		return "L"
	case Title:
		return "title"
	case Surname:
		return "sn"
	case GivenName:
		return "givenName"
	case Initials:
		return "initials"
	case Pseudonym:
		return "pseudonym"
	case GenerationQualifier:
		return "generationQualifier"
	case ElectronicMailAddress:
		return "email"
	case DomainComponent:
		return "DC"
	case Generic:
		return "Generic"
	default:
		return "UnKnown"
	}
}

// ToRFC4514FormatString returns an RFC4514 Format string of this AttributeTypeAndValue.
// The attribute type is uppercase
func (atv AttributeTypeAndValue) ToRFC4514FormatString() string {
	//https://www.rfc-editor.org/rfc/rfc4514#section-2.3
	return strings.ToUpper(atv.toShortName()) + "=" + atv.Value.ToRFC4514FormatString()
}

// String returns a string representation of this AttributeValue.
func (av AttributeValue) String() string {
	return av.Value
}

// ToRFC4514FormatString returns an RFC4514 Format string of this AttributeValue.
func (av AttributeValue) ToRFC4514FormatString() string {
	//https://www.rfc-editor.org/rfc/rfc4514#section-2.4
	return escapeAttributeValue(av.Value)
}

func needEscaping(r rune) bool {
	if r == '"' || r == '+' || r == ',' || r == ';' || r == '<' || r == '>' || r == '\\' || r == 0x0000 {
		//https://www.rfc-editor.org/rfc/rfc4514#section-2.4
		//- one of the characters '"', '+', ',', ';', '<', '>',  or '\'
		//(U+0022, U+002B, U+002C, U+003B, U+003C, U+003E, or U+005C, respectively);
		//- the null (U+0000) character.
		return true
	}
	return false
}

func escapeAttributeValue(s string) string {
	cnt := 0
	lastIndex := utf8.RuneCountInString(s) - 1
	var out string
	for _, r := range s {
		if cnt == 0 && r == ' ' || r == '#' {
			//https://www.rfc-editor.org/rfc/rfc4514#section-2.4
			//- a space (' ' U+0020) or number sign ('#' U+0023) occurring at the beginning of the string;
			out = out + escape(string(r))
			cnt++
			continue
		}

		if cnt == lastIndex && r == ' ' {
			//https://www.rfc-editor.org/rfc/rfc4514#section-2.4
			//- a space (' ' U+0020) character occurring at the end of the string;
			out = out + escape(string(r))
			cnt++
			continue
		}

		if needEscaping(r) {
			//https://www.rfc-editor.org/rfc/rfc4514#section-2.4
			out = out + escape(string(r))
			cnt++
			continue
		}

		out = out + string(r)
		cnt++
	}
	return out
}

func escape(c string) string {
	return "\\" + c
}

type Encoding int

const (
	PrintableString Encoding = iota + 1
	UTF8String
	IA5String
)

func convertToAttributeValue(r asn1.RawValue) (av AttributeValue, err error) {
	var p string
	var st string
	switch r.Tag {
	case asn1.TagPrintableString:
		av.Encoding = PrintableString
		p = "printable"
	case asn1.TagUTF8String:
		av.Encoding = UTF8String
		p = "utf8"
	case asn1.TagIA5String:
		av.Encoding = IA5String
		p = "ia5"
	default:
		err = errors.New("AttributeValue contains unsupported string encoding")
		return AttributeValue{}, err
	}
	rest, err := asn1.UnmarshalWithParams(r.FullBytes, &st, p)
	if err != nil {
		err := fmt.Errorf("AttributeValue parsing error: %w", err)
		return AttributeValue{}, err
	} else if len(rest) != 0 {
		err := fmt.Errorf("AttributeValue parsing error: trailing data after AttributeValue")
		return AttributeValue{}, err
	}
	av.Value = st
	return av, nil
}

func convertToAttributeTypeAndValue(iatv innerAttributeTypeAndValue) (AttributeTypeAndValue, error) {
	av, err := convertToAttributeValue(iatv.Value)
	if err != nil {
		err := fmt.Errorf("AttributeTypeAndValue parsing error: %w", err)
		return AttributeTypeAndValue{}, err
	}

	if !isDefinedOid(iatv.Type) {
		return AttributeTypeAndValue{Type: Generic, Oid: iatv.Type.String(), Value: av}, nil
	}

	atvn, _ := ReferAttributeTypeName(iatv.Type)
	atv := AttributeTypeAndValue{Type: atvn, Value: av}
	return atv, nil
}

func convertToRdn(irdn innerRDNSET) (RDN, error) {
	var atvs []AttributeTypeAndValue
	for index, iatv := range irdn {
		atv, err := convertToAttributeTypeAndValue(iatv)
		if err != nil {
			err := fmt.Errorf("%d th AttributeTypeAndValue element parsing error: %w", index, err)
			return RDN{}, err
		}
		atvs = append(atvs, atv)
	}
	return atvs, nil
}

func convertToDn(idn innerDN) (DN, error) {
	var rdns []RDN
	if len(rdns) == 0 {
		rdns = DN{}
	}
	for index, irdn := range idn {
		rdn, err := convertToRdn(irdn)
		if err != nil {
			err := fmt.Errorf("%d th RDN element parsing error: %w", index, err)
			return DN{}, err
		}
		rdns = append(rdns, rdn)
	}
	return rdns, nil
}

// ParseDERDN parses a distinguished name, ASN.1 DER form and returns DN.
// RelativeDistinguishedName of the distinguished name should have at least one AttributeTypeAndValue.
// AttributeValue currently supports the following ASN.1 string encodings:
//
//	PrintableString
//	UTF8String
//	IA5String
//
// Currently, the following combinations of OBJECT IDENTIFIER for AttributeType
// and Encoding for AttributeValue are supported:
//
//	2.5.4.6 (CountryName) : PrintableString
//	2.5.4.10 (OrganizationName) : PrintableString or UTF8String
//	2.5.4.11 (OrganizationalUnit) : PrintableString or UTF8String
//	2.5.4.46 (DnQualifier) : PrintableString
//	2.5.4.8 (StateOrProvinceName) : PrintableString or UTF8String
//	2.5.4.3 (CommonName) : PrintableString or UTF8String
//	2.5.4.5 (SerialNumber) : PrintableString
//	2.5.4.7 (LocalityName) : PrintableString or UTF8String
//	2.5.4.12 (Title) : PrintableString or UTF8String
//	2.5.4.4 (Surname) : PrintableString or UTF8String
//	2.5.4.42 (GivenName) : PrintableString or UTF8String
//	2.5.4.43 (Initials) : PrintableString or UTF8String
//	2.5.4.65 (Pseudonym) : PrintableString or UTF8String
//	2.5.4.44 (GenerationQualifier) : PrintableString or UTF8String
//	1.2.840.113549.1.9.1 (ElectronicMailAddress) : IA5String
//	0.9.2342.19200300.100.1.25 (DomainComponent) : IA5String
//	Any OBJECT IDENTIFIER other than those already listed (Generic) : PrintableString or UTF8String or IA5String
//
// https://datatracker.ietf.org/doc/html/rfc5280#section-4.1.2.4
// https://datatracker.ietf.org/doc/html/rfc5280#appendix-A.1
func ParseDERDN(dnBytes []byte) (dn DN, err error) {
	var idn innerDN
	err = idn.unmarshal(dnBytes)
	if err != nil {
		err := fmt.Errorf("unable to parse der DN: %w", err)
		return nil, err
	}
	dn, err = convertToDn(idn)
	if err != nil {
		err := fmt.Errorf("unable to parse der DN: %w", err)
		return nil, err
	}

	if isValid, err := isValidDN(dn); isValid == false {
		err := fmt.Errorf("unable to parse der DN: %w", err)
		return nil, err
	}

	return dn, nil
}

func convertToObjectIdentifier(o string) (oid asn1.ObjectIdentifier, err error) {
	sa := strings.Split(o, ".")
	if len(sa) == 0 {
		return nil, errors.New("ObjectIdentifier has no elements")
	}
	for _, s := range sa {
		c, err := strconv.Atoi(s)
		if c < 0 {
			err := errors.New("ObjectIdentifier convert error: OID value must not be a negative number")
			return nil, err
		}

		if err != nil {
			err := fmt.Errorf("ObjectIdentifier convert error: %w", err)
			return nil, err
		}
		oid = append(oid, c)
	}
	return oid, nil
}

func convertToInnerAttributeTypeAndValue(atv AttributeTypeAndValue) (innerAttributeTypeAndValue, error) {
	v := atv.Value
	srv, err := newStringRawValue(v.Encoding, v.Value)
	if err != nil {
		err := fmt.Errorf("AttributeTypeAndValue marshal error: %w", err)
		return innerAttributeTypeAndValue{}, err
	}

	var oid asn1.ObjectIdentifier
	t := atv.Type
	if t == Generic {
		if oid, err = convertToObjectIdentifier(atv.Oid); err != nil {
			return innerAttributeTypeAndValue{}, err
		}
		return innerAttributeTypeAndValue{Type: oid, Value: srv}, nil
	}

	oid, err = ReferOid(t)
	if err != nil {
		err := fmt.Errorf("AttributeTypeAndValue marshal error: %w", err)
		if err != nil {
			return innerAttributeTypeAndValue{}, err
		}
	}
	return innerAttributeTypeAndValue{Type: oid, Value: srv}, nil
}

func convertToInnerRDNSET(rdn RDN) (innerRDNSET, error) {
	var iatvs []innerAttributeTypeAndValue
	for index, atv := range rdn {
		iatv, err := convertToInnerAttributeTypeAndValue(atv)
		if err != nil {
			err := fmt.Errorf("%d th AttributeTypeAndValue element marshal error: %w", index, err)
			return innerRDNSET{}, err
		}
		iatvs = append(iatvs, iatv)
	}
	return iatvs, nil
}

func convertToInnerDN(dn DN) (innerDN, error) {
	var idns []innerRDNSET
	if dn.CountRDN() == 0 {
		idns = innerDN{}
	}
	for index, rdn := range dn {
		irdn, err := convertToInnerRDNSET(rdn)
		if err != nil {
			err := fmt.Errorf("%d th RDN element marshal error: %w", index, err)
			return innerDN{}, err
		}
		idns = append(idns, irdn)
	}
	return idns, nil
}

// MarshalDN converts a DN to distinguished name (DN), ASN.1 DER form.
// RDN of the DN should have at least one AttributeTypeAndValue element.
// AttributeValue currently supports the following ASN.1 string encodings:
//
//	PrintableString
//	UTF8String
//	IA5String
//
// AttributeType currently supports the following AttributeTypes:
//
//	CountryName (2.5.4.6)
//	OrganizationName (2.5.4.10)
//	OrganizationalUnit (2.5.4.11)
//	DnQualifier (2.5.4.46)
//	StateOrProvinceName (2.5.4.8)
//	CommonName (2.5.4.3)
//	SerialNumber (2.5.4.5)
//	LocalityName (2.5.4.7)
//	Title (2.5.4.12)
//	Surname (2.5.4.4)
//	GivenName (2.5.4.42)
//	Initials (2.5.4.43)
//	Pseudonym (2.5.4.65)
//	GenerationQualifier (2.5.4.44)
//	ElectronicMailAddress (1.2.840.113549.1.9.1)
//	DomainComponent (0.9.2342.19200300.100.1.25)
//	Generic (Any OBJECT IDENTIFIER)
//
// Any object identifier can be specified by setting Generic to Type and object identifier to Oid.
// If Type is Generic, Oid must be specified.
//
// Currently, the following combinations of OBJECT IDENTIFIER for AttributeType
// and Encoding for AttributeValue are supported:
//
//	CountryName (2.5.4.6) : PrintableString
//	OrganizationName (2.5.4.10) : PrintableString or UTF8String
//	OrganizationalUnit (2.5.4.11) : PrintableString or UTF8String
//	DnQualifier (2.5.4.46) : PrintableString
//	StateOrProvinceName (2.5.4.8) : PrintableString or UTF8String
//	CommonName (2.5.4.3) : PrintableString or UTF8String
//	SerialNumber (2.5.4.5) : PrintableString
//	LocalityName (2.5.4.7) : PrintableString or UTF8String
//	Title (2.5.4.12) : PrintableString or UTF8String
//	Surname (2.5.4.4) : PrintableString or UTF8String
//	GivenName (2.5.4.42) : PrintableString or UTF8String
//	Initials (2.5.4.43) : PrintableString or UTF8String
//	Pseudonym (2.5.4.65) : PrintableString or UTF8String
//	GenerationQualifier (2.5.4.44) : PrintableString or UTF8String
//	ElectronicMailAddress (1.2.840.113549.1.9.1) : IA5String
//	DomainComponent (0.9.2342.19200300.100.1.25) : IA5String
//	Generic (Any OBJECT IDENTIFIER other than those already listed) : PrintableString or UTF8String or IA5String
//
// https://datatracker.ietf.org/doc/html/rfc5280#section-4.1.2.4
// https://datatracker.ietf.org/doc/html/rfc5280#appendix-A.1
func MarshalDN(dn DN) (dnBytes []byte, err error) {
	if isValid, err := isValidDN(dn); isValid == false {
		err := fmt.Errorf("unable to marshal DN: %w", err)
		return nil, err
	}

	idn, err := convertToInnerDN(dn)
	if err != nil {
		err := fmt.Errorf("unable to marshal DN: %w", err)
		return nil, err
	}

	b, err := idn.marshal()
	if err != nil {
		err := fmt.Errorf("unable to marshal DN: %w", err)
		return nil, err
	}
	return b, nil
}

func (e Encoding) String() string {
	switch e {
	case PrintableString:
		return "PrintableString"
	case UTF8String:
		return "UTF8String"
	case IA5String:
		return "IA5String"
	default:
		return "Not Supported Encoding"
	}
}

// marshal returns the DER-encoded ASN.1 data dnAsn1Bytes of id.
func (id *innerDN) marshal() (dnAsn1Bytes []byte, err error) {
	b, err := asn1.Marshal(*id)
	if err != nil {
		err := fmt.Errorf("marshal error: %w", err)
		return nil, err
	}
	return b, nil
}

// unmarshal parses the DER-encoded ASN.1 data dnAsn1Bytes and fills in id.
func (id *innerDN) unmarshal(dnAsn1Bytes []byte) (err error) {
	if rest, err := asn1.Unmarshal(dnAsn1Bytes, id); err != nil {
		err := fmt.Errorf("unmarshal error: %w", err)
		return err
	} else if len(rest) != 0 {
		err := fmt.Errorf("unmarshal error: trailing data after DN")
		return err
	}
	return err
}

// newStringRawValue constructs new RawValue instance of st encoded with specified e.
// e can specify PrintableString, UTF8string, IA5String encoding only.
// TeletexString, UniversalString, BMPString are not supported.
func newStringRawValue(e Encoding, st string) (r asn1.RawValue, err error) {
	var b []byte
	var p string
	var t int
	switch e {
	case PrintableString:
		p = "printable"
		t = asn1.TagPrintableString
	case UTF8String:
		p = "utf8"
		t = asn1.TagUTF8String
	case IA5String:
		p = "ia5"
		t = asn1.TagIA5String
	default:
		err = fmt.Errorf("%d is not supported string encoding type", e)
		return asn1.RawValue{}, err
	}
	b, err = asn1.MarshalWithParams(st, p)
	if err != nil {
		err = fmt.Errorf("AttributeValue creating error: %w", err)
		return asn1.RawValue{}, err
	}
	r = asn1.RawValue{
		Tag:       t,
		FullBytes: b,
	}
	return r, nil
}

// ReferOid returns corresponding ObjectIdentifier of atn.
// If not supported AttributeType is specified, then returns blank ObjectIdentifier and error.
// The following AttributeType are currently supported:
//
//	2.5.4.6  CountryName
//	2.5.4.10  OrganizationName
//	2.5.4.11  OrganizationalUnit
//	2.5.4.46  DnQualifier
//	2.5.4.8  StateOrProvinceName
//	2.5.4.3  CommonName
//	2.5.4.5  SerialNumber
//	2.5.4.7  LocalityName
//	2.5.4.12  Title
//	2.5.4.4  Surname
//	2.5.4.42  GivenName
//	2.5.4.43  Initials
//	2.5.4.65  Pseudonym
//	2.5.4.44  GenerationQualifier
//	1.2.840.113549.1.9.1  ElectronicMailAddress
//	0.9.2342.19200300.100.1.25  DomainComponent
//
// https://datatracker.ietf.org/doc/html/rfc5280#section-4.1.2.4
// https://datatracker.ietf.org/doc/html/rfc5280#appendix-A.1
func ReferOid(atn AttributeType) (oid asn1.ObjectIdentifier, err error) {
	switch atn {
	case CountryName:
	case OrganizationName:
	case OrganizationalUnit:
	case DnQualifier:
	case StateOrProvinceName:
	case CommonName:
	case SerialNumber:
	case LocalityName:
	case Title:
	case Surname:
	case GivenName:
	case Initials:
	case Pseudonym:
	case GenerationQualifier:
	case ElectronicMailAddress:
	case DomainComponent:
	default:
		err = fmt.Errorf("not supported AttributeType")
		return asn1.ObjectIdentifier{}, err
	}
	return oidTable[atn], nil
}

// ReferAttributeTypeName returns corresponding AttributeType of ObjectIdentifier.
// If not supported ObjectIdentifier is specified, then returns 0 and error.
// The following ObjectIdentifier are currently supported:
//
//	2.5.4.6  CountryName
//	2.5.4.10  OrganizationName
//	2.5.4.11  OrganizationalUnit
//	2.5.4.46  DnQualifier
//	2.5.4.8  StateOrProvinceName
//	2.5.4.3  CommonName
//	2.5.4.5  SerialNumber
//	2.5.4.7  LocalityName
//	2.5.4.12  Title
//	2.5.4.4  Surname
//	2.5.4.42  GivenName
//	2.5.4.43  Initials
//	2.5.4.65  Pseudonym
//	2.5.4.44  GenerationQualifier
//	1.2.840.113549.1.9.1  ElectronicMailAddress
//	0.9.2342.19200300.100.1.25  DomainComponent
//
// https://datatracker.ietf.org/doc/html/rfc5280#section-4.1.2.4
// https://datatracker.ietf.org/doc/html/rfc5280#appendix-A.1
func ReferAttributeTypeName(oid asn1.ObjectIdentifier) (atn AttributeType, err error) {
	if isDefinedOid(oid) {
		return attributeTypeTable[oid.String()], nil
	}
	return 0, fmt.Errorf("%s is not supported AttributeType oid", oid.String())
}

func isDefinedOid(oid asn1.ObjectIdentifier) bool {
	switch oid.String() {
	case asn1.ObjectIdentifier{2, 5, 4, 6}.String():
	case asn1.ObjectIdentifier{2, 5, 4, 10}.String():
	case asn1.ObjectIdentifier{2, 5, 4, 11}.String():
	case asn1.ObjectIdentifier{2, 5, 4, 46}.String():
	case asn1.ObjectIdentifier{2, 5, 4, 8}.String():
	case asn1.ObjectIdentifier{2, 5, 4, 3}.String():
	case asn1.ObjectIdentifier{2, 5, 4, 5}.String():
	case asn1.ObjectIdentifier{2, 5, 4, 7}.String():
	case asn1.ObjectIdentifier{2, 5, 4, 12}.String():
	case asn1.ObjectIdentifier{2, 5, 4, 4}.String():
	case asn1.ObjectIdentifier{2, 5, 4, 42}.String():
	case asn1.ObjectIdentifier{2, 5, 4, 43}.String():
	case asn1.ObjectIdentifier{2, 5, 4, 65}.String():
	case asn1.ObjectIdentifier{2, 5, 4, 44}.String():
	case asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 1}.String():
	case asn1.ObjectIdentifier{0, 9, 2342, 19200300, 100, 1, 25}.String():
	default:
		return false
	}
	return true
}

// isDirectoryString reports whether tn(tag number) is DirectoryString.
func isDirectoryString(tn int) (result bool) {
	switch tn {
	case asn1.TagT61String: //aka TeletexString
		result = true
	case asn1.TagPrintableString:
		result = true
	case 28: //UniversalString
		result = true
	case asn1.TagUTF8String:
		result = true
	case asn1.TagBMPString:
		result = true
	default:
		result = false
	}
	return result
}

// isIA5String reports whether tn(tag number) is IA5String.
func isIA5String(tn int) (result bool) {
	if tn == asn1.TagIA5String {
		return true
	}
	return false
}

// isPrintableString reports whether tn(tag number) is PrintableString.
func isPrintableString(tn int) (result bool) {
	if tn == asn1.TagPrintableString {
		return true
	}
	return false
}

// CountRDN returns number of RDN of DN.
func (d DN) CountRDN() int {
	return len(d)
}

// CountAttributeTypeAndValue returns number of AttributeTypeAndValue of RDN.
func (r RDN) CountAttributeTypeAndValue() int {
	return len(r)
}

// RetrieveRDN returns the rdn specified by index from the DN.
func (d DN) RetrieveRDN(index int) (rdn RDN, err error) {
	if index < 0 || index >= d.CountRDN() {
		return RDN{}, fmt.Errorf("index out of bounds error")
	}
	return d[index], nil
}

// RetrieveRDNsByOids returns RDN(s) that exactly match the specified oids, AttributeType Oid(s).
// The order of the AttributeType Oid(s) is ignored because AttributeType Oid(s) is ASN1.SET.
func (d DN) RetrieveRDNsByOids(oids []string) (rdns []RDN) {
	rdns = []RDN{}
	if len(oids) == 0 {
		return rdns
	}

	for i := 0; i < d.CountRDN(); i++ {
		if d[i].CountAttributeTypeAndValue() != len(oids) {
			continue
		}

		if !isMatchedRDNByOids(d[i], oids) {
			continue
		}

		rdns = append(rdns, d[i])
	}
	return rdns
}

// RetrieveRDNsByAttributeTypes returns RDN(s) that exactly match the specified ats AttributeType(s).
// Because ats is ASN1.SET, the order of ats is ignored.
// Deprecated: Replace with a RetrieveRDNsByOids implementation.
func (d DN) RetrieveRDNsByAttributeTypes(ats []AttributeType) (rdns []RDN) {
	rdns = []RDN{}
	if len(ats) == 0 {
		return rdns
	}

	for i := 0; i < d.CountRDN(); i++ {
		if d[i].CountAttributeTypeAndValue() != len(ats) {
			continue
		}

		if !isMatchedRDN(d[i], ats) {
			continue
		}

		rdns = append(rdns, d[i])
	}
	return rdns
}

// isMatchedRDN reports whether AttributeType of AttributeTypeAndValue of r RDN matches the specified ats AttributeType(s).
// Because ats is ASN1.SET, the order of ats is ignored.
func isMatchedRDN(r RDN, ats []AttributeType) (isMatched bool) {
	rest := r
	for i := 0; i < len(ats); i++ {
		if index := findMatchedAttributeTypeIndex(rest, ats[i]); index != -1 {
			rest = removeAttributeTypeAndValue(index, rest)
		}
	}

	if len(rest) != 0 {
		return false
	}

	return true
}

// isMatchedRDNByOids reports whether AttributeType of AttributeTypeAndValue of r RDN match oids, a set of AttributeType OIDs.
// Because oids is ASN1.SET, the order of oids is ignored.
func isMatchedRDNByOids(r RDN, oids []string) (isMatched bool) {
	rest := r
	for i := 0; i < len(oids); i++ {
		if index := findMatchedOidIndex(rest, oids[i]); index != -1 {
			rest = removeAttributeTypeAndValue(index, rest)
		}
	}

	if len(rest) != 0 {
		return false
	}

	return true
}

// removeAttributeTypeAndValue removes AttributeTypeAndValue specified by index i from r and returns it.
func removeAttributeTypeAndValue(index int, r RDN) (rest RDN) {
	rest = make(RDN, len(r), len(r))
	copy(rest, r)
	rest = append(rest[:index], rest[index+1:]...)
	return rest
}

// findMatchedAttributeTypeIndex finds index of AttributeTypeAndValue in the RDN by att, the AttributeType.
func findMatchedAttributeTypeIndex(r RDN, att AttributeType) (index int) {
	for i := 0; i < r.CountAttributeTypeAndValue(); i++ {
		if r[i].Type == att {
			return i
		}
	}
	return -1
}

// findMatchedOidIndex finds the index of AttributeTypeAndValue in the RDN by oid, the AttributeType OID.
func findMatchedOidIndex(r RDN, oid string) (index int) {
	for i := 0; i < r.CountAttributeTypeAndValue(); i++ {
		if r[i].Type == Generic {
			if r[i].Oid == oid {
				return i
			}
		}

		o, _ := ReferOid(r[i].Type)
		if o.String() == oid {
			return i
		}
	}
	return -1
}

func isValidAttributeValueEncoding(av AttributeValue) (isValid bool, err error) {
	switch av.Encoding {
	case PrintableString:
	case UTF8String:
	case IA5String:
	default:
		return false, fmt.Errorf("not supported string encoding error")
	}
	return true, nil
}

func isValidAttributeTypeAndValue(atv AttributeTypeAndValue) (isValid bool, err error) {
	if isValid, err = isValidAttributeType(atv.Type); isValid != true {
		return false, fmt.Errorf("AttributeTypeAndValue error: %w", err)
	}
	if isValid, err = isValidAttributeValueEncoding(atv.Value); isValid != true {
		return false, fmt.Errorf("AttributeTypeAndValue error: %w", err)
	}

	if atv.Type == Generic {
		var o asn1.ObjectIdentifier
		var at AttributeType
		if o, err = convertToObjectIdentifier(atv.Oid); err != nil {
			return false, fmt.Errorf("AttributeTypeAndValue error: %w", err)
		}

		//Check if Oid is one of the member of AttributeType ObjectIdentifier except Generic
		if isDefinedOid(o) {
			at, err = ReferAttributeTypeName(o)
			if err != nil {
				return false, fmt.Errorf("AttributeTypeAndValue error: %w", err)
			}

			//Oid is one of the member of AttributeTypes except Generic
			if isValid, err = isValidAttributeTypeAndAttributeValueComb(at, atv.Value); isValid != true {
				return false, fmt.Errorf("AttributeTypeAndValue error: %w", err)
			}
		}
	}

	if isValid, err = isValidAttributeTypeAndAttributeValueComb(atv.Type, atv.Value); isValid != true {
		return false, fmt.Errorf("AttributeTypeAndValue error: %w", err)
	}
	return true, nil
}

func isValidRDN(r RDN) (isValid bool, err error) {
	isValid = false
	if r.CountAttributeTypeAndValue() == 0 {
		return isValid, errors.New("RDN should have at least one AttributeTypeAndValue")
	}
	for index, atv := range r {
		isValid, err = isValidAttributeTypeAndValue(atv)
		if err != nil {
			err := fmt.Errorf("%d th AttributeTypeAndValue element validating error: %w", index, err)
			return isValid, err
		}
	}
	return isValid, nil
}

func isValidDN(d DN) (isValid bool, err error) {
	isValid = false
	if d.CountRDN() == 0 {
		isValid = true
	}
	for index, rdn := range d {
		isValid, err = isValidRDN(rdn)
		if err != nil {
			err := fmt.Errorf("%d th RDN element validating error: %w", index, err)
			return isValid, err
		}
	}
	return isValid, nil
}

// isPrintableStringOrUTF8StringOrIA5StringEncoding reports whether e is PrintableString or UTF8String or IA5String.
func isPrintableStringOrUTF8StringOrIA5StringEncoding(e Encoding) (ok bool) {
	switch e {
	case PrintableString:
		return true
	case UTF8String:
		return true
	case IA5String:
		return true
	default:
		return false
	}
}

// isPrintableStringOrUTF8StringEncoding reports whether e is PrintableString or UTF8String.
func isPrintableStringOrUTF8StringEncoding(e Encoding) (ok bool) {
	switch e {
	case PrintableString:
		return true
	case UTF8String:
		return true
	default:
		return false
	}
}

// isIA5StringEncoding reports whether e is IA5String.
func isIA5StringEncoding(e Encoding) (ok bool) {
	if e == IA5String {
		return true
	}
	return false
}

// isPrintableStringEncoding reports whether e is PrintableString.
func isPrintableStringEncoding(e Encoding) (ok bool) {
	if e == PrintableString {
		return true
	}
	return false
}

func isValidAttributeTypeAndAttributeValueComb(at AttributeType, av AttributeValue) (isValid bool, err error) {
	ok := true
	p := PrintableString.String()
	pou := PrintableString.String() + " or " + UTF8String.String()
	pouoia5 := PrintableString.String() + " or " + UTF8String.String() + " or " + IA5String.String()
	ia5 := IA5String.String()
	var enlabel string
	switch at {
	case CountryName:
		if !isPrintableStringEncoding(av.Encoding) {
			enlabel = p
			ok = false
		}
	case OrganizationName:
		if !isPrintableStringOrUTF8StringEncoding(av.Encoding) {
			enlabel = pou
			ok = false
		}
	case OrganizationalUnit:
		if !isPrintableStringOrUTF8StringEncoding(av.Encoding) {
			enlabel = pou
			ok = false
		}
	case DnQualifier:
		if !isPrintableStringEncoding(av.Encoding) {
			enlabel = p
			ok = false
		}
	case StateOrProvinceName:
		if !isPrintableStringOrUTF8StringEncoding(av.Encoding) {
			enlabel = pou
			ok = false
		}
	case CommonName:
		if !isPrintableStringOrUTF8StringEncoding(av.Encoding) {
			enlabel = pou
			ok = false
		}
	case SerialNumber:
		if !isPrintableStringEncoding(av.Encoding) {
			enlabel = p
			ok = false
		}
	case LocalityName:
		if !isPrintableStringOrUTF8StringEncoding(av.Encoding) {
			enlabel = pou
			ok = false
		}
	case Title:
		if !isPrintableStringOrUTF8StringEncoding(av.Encoding) {
			enlabel = pou
			ok = false
		}
	case Surname:
		if !isPrintableStringOrUTF8StringEncoding(av.Encoding) {
			enlabel = pou
			ok = false
		}
	case GivenName:
		if !isPrintableStringOrUTF8StringEncoding(av.Encoding) {
			enlabel = pou
			ok = false
		}
	case Initials:
		if !isPrintableStringOrUTF8StringEncoding(av.Encoding) {
			enlabel = pou
			ok = false
		}
	case Pseudonym:
		if !isPrintableStringOrUTF8StringEncoding(av.Encoding) {
			enlabel = pou
			ok = false
		}
	case GenerationQualifier:
		if !isPrintableStringOrUTF8StringEncoding(av.Encoding) {
			enlabel = pou
			ok = false
		}
	case ElectronicMailAddress:
		if !isIA5StringEncoding(av.Encoding) {
			enlabel = ia5
			ok = false
		}
	case DomainComponent:
		if !isIA5StringEncoding(av.Encoding) {
			enlabel = ia5
			ok = false
		}
	case Generic:
		if !isPrintableStringOrUTF8StringOrIA5StringEncoding(av.Encoding) {
			enlabel = pouoia5
			ok = false
		}
	default:
		return false, fmt.Errorf("not supported AttributeType error")
	}

	if !ok {
		return false, fmt.Errorf("%s’s value should be %s", at.String(), enlabel)
	}
	return true, nil
}

func isValidAttributeType(at AttributeType) (isValid bool, err error) {
	switch at {
	case CountryName:
	case OrganizationName:
	case OrganizationalUnit:
	case DnQualifier:
	case StateOrProvinceName:
	case CommonName:
	case SerialNumber:
	case LocalityName:
	case Title:
	case Surname:
	case GivenName:
	case Initials:
	case Pseudonym:
	case GenerationQualifier:
	case ElectronicMailAddress:
	case DomainComponent:
	case Generic:
	default:
		return false, fmt.Errorf("not supported AttributeType error")
	}
	return true, nil
}
