package dnutil

import (
	"encoding/asn1"
	"encoding/hex"
	"reflect"
	"testing"
)

func decode(hs string) []byte {
	b, _ := hex.DecodeString(hs)
	return b
}

var (
	r1   = asn1.RawValue{Tag: asn1.TagPrintableString, Bytes: decode("4A50"), FullBytes: decode("13024A50")}     //PrintableString JP
	r2   = asn1.RawValue{Tag: asn1.TagPrintableString, Bytes: decode("616263"), FullBytes: decode("1303616263")} //PrintableString abc
	r3   = asn1.RawValue{Tag: asn1.TagUTF8String, Bytes: decode("616263"), FullBytes: decode("0C03616263")}      //UTF8String abc
	atv1 = innerAttributeTypeAndValue{
		Type:  []int{2, 5, 4, 10},
		Value: r3,
	}
	atv2 = innerAttributeTypeAndValue{
		Type:  []int{2, 5, 4, 6},
		Value: r1,
	}
	atv3 = innerAttributeTypeAndValue{
		Type:  []int{2, 5, 4, 10},
		Value: r2,
	}
	rdn1        = innerRDNSET([]innerAttributeTypeAndValue{atv2})
	rdn2        = innerRDNSET([]innerAttributeTypeAndValue{atv1})
	rdn3        = innerRDNSET([]innerAttributeTypeAndValue{atv1, atv3})
	dn1         = innerDN{rdn1, rdn2}
	dn2         = innerDN{rdn1, rdn3}
	dn1bytes, _ = hex.DecodeString("301B310B3009060355040613024A50310C300A060355040A0C03616263")
	dn2bytes, _ = hex.DecodeString("3027310b3009060355040613024a503118300a060355040a0c03616263300a060355040a1303616263")
)

func Test_newStringRawValue(t *testing.T) {
	type args struct {
		e  Encoding
		st string
	}
	tests := []struct {
		name    string
		args    args
		wantR   asn1.RawValue
		wantErr bool
	}{
		{"TestCase:PrintableString,JP", args{PrintableString, "JP"}, asn1.RawValue{Tag: asn1.TagPrintableString, FullBytes: decode("13024A50")}, false},
		{"TestCase:UTF8String,日本語", args{UTF8String, "日本語"}, asn1.RawValue{Tag: asn1.TagUTF8String, FullBytes: decode("0C09E697A5E69CACE8AA9E")}, false},
		{"TestCase:IA5String,a@example.com", args{IA5String, "a@example.com"}, asn1.RawValue{Tag: asn1.TagIA5String, FullBytes: decode("160D61406578616D706C652E636F6D")}, false},
		{"TestCase:NotSupportedEncoding,JP", args{Encoding(6), "JP"}, asn1.RawValue{}, true},
		{"TestCase:PrintableString,a@example.com", args{PrintableString, "a@example.com"}, asn1.RawValue{}, true},
		{"TestCase:IA5String,日本語", args{IA5String, "日本語"}, asn1.RawValue{}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotR, err := newStringRawValue(tt.args.e, tt.args.st)
			if (err != nil) != tt.wantErr {
				t.Errorf("newStringRawValue() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(gotR, tt.wantR) {
				t.Errorf("newStringRawValue() gotR = %v, want %v", gotR, tt.wantR)
			}
		})
	}
}

func TestReferOid(t *testing.T) {
	type args struct {
		atn AttributeType
	}
	tests := []struct {
		name    string
		args    args
		wantOid asn1.ObjectIdentifier
		wantErr bool
	}{
		{"TestCase:CountryName", args{CountryName}, []int{2, 5, 4, 6}, false},
		{"TestCase:OrganizationName", args{OrganizationName}, []int{2, 5, 4, 10}, false},
		{"TestCase:OrganizationalUnit", args{OrganizationalUnit}, []int{2, 5, 4, 11},
			false},
		{"TestCase:DnQualifier", args{DnQualifier}, []int{2, 5, 4, 46}, false},
		{"TestCase:StateOrProvinceName", args{StateOrProvinceName}, []int{2, 5, 4, 8}, false},
		{"TestCase:CommonName", args{CommonName}, []int{2, 5, 4, 3}, false},
		{"TestCase:SerialNumber", args{SerialNumber}, []int{2, 5, 4, 5}, false},
		{"TestCase:LocalityName", args{LocalityName}, []int{2, 5, 4, 7}, false},
		{"TestCase:Title", args{Title}, []int{2, 5, 4, 12}, false},
		{"TestCase:Surname", args{Surname}, []int{2, 5, 4, 4}, false},
		{"TestCase:GivenName", args{GivenName}, []int{2, 5, 4, 42}, false},
		{"TestCase:Initials", args{Initials}, []int{2, 5, 4, 43}, false},
		{"TestCase:Pseudonym", args{Pseudonym}, []int{2, 5, 4, 65}, false},
		{"TestCase:GenerationQualifier", args{GenerationQualifier}, []int{2, 5, 4, 44}, false},
		{"TestCase:ElectronicMailAddress", args{ElectronicMailAddress}, []int{1, 2, 840, 113549, 1, 9, 1}, false},
		{"TestCase:DomainComponent", args{DomainComponent}, []int{0, 9, 2342, 19200300, 100, 1, 25}, false},
		{"TestCase:UnKnownAttributeType", args{AttributeType(9999)}, asn1.ObjectIdentifier{}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotOid, err := ReferOid(tt.args.atn)
			if (err != nil) != tt.wantErr {
				t.Errorf("ReferOid() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(gotOid, tt.wantOid) {
				t.Errorf("ReferOid() gotOid = %v, want %v", gotOid, tt.wantOid)
			}
		})
	}
}

func Test_isDirectoryString(t *testing.T) {
	type args struct {
		tn int
	}
	tests := []struct {
		name       string
		args       args
		wantResult bool
	}{
		{"TestCase:T61String or TeletexString", args{asn1.TagT61String}, true},
		{"TestCase:PrintableString", args{asn1.TagPrintableString}, true},
		{"TestCase:UniversalString", args{28}, true},
		{"TestCase:UTF8String", args{asn1.TagUTF8String}, true},
		{"TestCase:BMPString", args{asn1.TagBMPString}, true},
		{"TestCase:Other encoding", args{asn1.TagIA5String}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if gotResult := isDirectoryString(tt.args.tn); gotResult != tt.wantResult {
				t.Errorf("isDirectoryString() = %v, want %v", gotResult, tt.wantResult)
			}
		})
	}
}

func Test_isIA5String(t *testing.T) {
	type args struct {
		tn int
	}
	tests := []struct {
		name       string
		args       args
		wantResult bool
	}{
		{"TestCase:IA5String", args{asn1.TagIA5String}, true},
		{"TestCase:Other encoding", args{asn1.TagBMPString}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if gotResult := isIA5String(tt.args.tn); gotResult != tt.wantResult {
				t.Errorf("isIA5String() = %v, want %v", gotResult, tt.wantResult)
			}
		})
	}
}

func Test_isPrintableString(t *testing.T) {
	type args struct {
		tn int
	}
	tests := []struct {
		name       string
		args       args
		wantResult bool
	}{
		{"TestCase:PrintableString", args{asn1.TagPrintableString}, true},
		{"TestCase:Other encoding", args{asn1.TagBMPString}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if gotResult := isPrintableString(tt.args.tn); gotResult != tt.wantResult {
				t.Errorf("isPrintableString() = %v, want %v", gotResult, tt.wantResult)
			}
		})
	}
}

func Test_marshal(t *testing.T) {
	tests := []struct {
		name            string
		id              innerDN
		wantDnAsn1Bytes []byte
		wantErr         bool
	}{
		{"TestCase:zero rdn", innerDN{}, decode("3000"), false},
		{"TestCase:single rdn", dn1, dn1bytes, false},
		{"TestCase:multi value rdn", dn2, dn2bytes, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotDnAsn1Bytes, err := tt.id.marshal()
			if (err != nil) != tt.wantErr {
				t.Errorf("marshal() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(gotDnAsn1Bytes, tt.wantDnAsn1Bytes) {
				t.Errorf("marshal() gotDnAsn1Bytes = %v, want %v", gotDnAsn1Bytes, tt.wantDnAsn1Bytes)
			}
		})
	}
}

func Test_unmarshal(t *testing.T) {
	dn3bytes := decode("300d310b300906035504031e020061")
	dn3 := innerDN{
		innerRDNSET{
			innerAttributeTypeAndValue{
				Type: asn1.ObjectIdentifier{2, 5, 4, 3},
				Value: asn1.RawValue{
					Tag:       30,
					Bytes:     decode("0061"),
					FullBytes: decode("1e020061"),
				},
			},
		},
	}
	type args struct {
		dnAsn1Bytes []byte
	}
	tests := []struct {
		name    string
		dn      innerDN
		args    args
		wantDn  innerDN
		wantErr bool
	}{
		{"TestCase:single rdn", innerDN{}, args{dn1bytes}, dn1, false},
		{"TestCase:multi value rdn", innerDN{}, args{dn2bytes}, dn2, false},
		{"TestCase:single rdn single atv - CN=a (BMPString) ", innerDN{}, args{dn3bytes}, dn3, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := tt.dn.unmarshal(tt.args.dnAsn1Bytes); (err != nil) != tt.wantErr {
				t.Errorf("unmarshal() error = %v, wantErr %v", err, tt.wantErr)
			}
			if !reflect.DeepEqual(tt.dn, tt.wantDn) {
				t.Errorf("unmarshal() gotDn = %v, want %v", tt.dn, tt.wantDn)
			}
		})
	}
}

func Test_convertToAttributeValue(t *testing.T) {
	var r1 = asn1.RawValue{Tag: asn1.TagPrintableString, Bytes: decode("4A50"), FullBytes: decode("13024A50")}                                       //PrintableString JP
	var r2 = asn1.RawValue{Tag: asn1.TagUTF8String, Bytes: decode("E697A5E69CAC"), FullBytes: decode("0C06E697A5E69CAC")}                            //UTF8String 日本
	var r3 = asn1.RawValue{Tag: asn1.TagIA5String, Bytes: decode("61406578616D706C652E636F6D"), FullBytes: decode("160D61406578616D706C652E636F6D")} //IA5String a@example.com
	var r4 = asn1.RawValue{Tag: asn1.TagBMPString, Bytes: decode("006100620063"), FullBytes: decode("1E06006100620063")}                             //BMPString JP
	var r5 = asn1.RawValue{Tag: asn1.TagPrintableString, Bytes: decode("AAA"), FullBytes: decode("AAA")}                                             //Broken Data
	type args struct {
		r asn1.RawValue
	}
	tests := []struct {
		name    string
		args    args
		wantAv  AttributeValue
		wantErr bool
	}{
		{"TestCase:PrintableString ", args{r1}, AttributeValue{Encoding: PrintableString, Value: "JP"}, false},
		{"TestCase:UTF8String ", args{r2}, AttributeValue{Encoding: UTF8String, Value: "日本"}, false},
		{"TestCase:IA5String ", args{r3}, AttributeValue{Encoding: IA5String, Value: "a@example.com"}, false},
		{"TestCase:BMPString ", args{r4}, AttributeValue{}, true},
		{"TestCase:PrintableString , Broken raw", args{r5}, AttributeValue{}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotAv, err := convertToAttributeValue(tt.args.r)
			if (err != nil) != tt.wantErr {
				t.Errorf("convertToAttributeValue() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(gotAv, tt.wantAv) {
				t.Errorf("convertToAttributeValue() gotAv = %v, want %v", gotAv, tt.wantAv)
			}
		})
	}
}

func Test_convertToAttributeTypeAndValue(t *testing.T) {
	var r1 = asn1.RawValue{Tag: asn1.TagPrintableString, Bytes: decode("4A50"), FullBytes: decode("13024A50")} //PrintableString JP
	var r2 = asn1.RawValue{Tag: asn1.TagPrintableString, Bytes: decode("AAA"), FullBytes: decode("AAA")}       //Broken Data

	var iatv1 = innerAttributeTypeAndValue{Type: asn1.ObjectIdentifier{2, 5, 4, 6}, Value: r1}
	var iatv2 = innerAttributeTypeAndValue{Type: asn1.ObjectIdentifier{2, 5, 4, 6}, Value: r2}
	var iatv3 = innerAttributeTypeAndValue{Type: asn1.ObjectIdentifier{9, 9, 9, 9}, Value: r1}

	type args struct {
		iatv innerAttributeTypeAndValue
	}
	tests := []struct {
		name    string
		args    args
		want    AttributeTypeAndValue
		wantErr bool
	}{
		{"TestCase:CountryName PrintableString JP", args{iatv1}, AttributeTypeAndValue{Type: CountryName, Value: AttributeValue{Encoding: PrintableString, Value: "JP"}}, false},
		{"TestCase:CountryName PrintableString Broken data", args{iatv2}, AttributeTypeAndValue{}, true},
		{"TestCase:Wrong OID PrintableString JP", args{iatv3}, AttributeTypeAndValue{}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := convertToAttributeTypeAndValue(tt.args.iatv)
			if (err != nil) != tt.wantErr {
				t.Errorf("convertToAttributeTypeAndValue() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("convertToAttributeTypeAndValue() got = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_convertToRdn(t *testing.T) {
	var r1 = asn1.RawValue{Tag: asn1.TagPrintableString, Bytes: decode("61"), FullBytes: decode("130161")}     //PrintableString a
	var r2 = asn1.RawValue{Tag: asn1.TagPrintableString, Bytes: decode("6161"), FullBytes: decode("13026161")} //PrintableString a

	var iatv1 = innerAttributeTypeAndValue{Type: asn1.ObjectIdentifier{2, 5, 4, 6}, Value: r1}
	var iatv2 = innerAttributeTypeAndValue{Type: asn1.ObjectIdentifier{2, 5, 4, 6}, Value: r2}
	var iatv3 = innerAttributeTypeAndValue{Type: asn1.ObjectIdentifier{9, 9, 9, 9}, Value: r1}

	type args struct {
		irdn innerRDNSET
	}
	tests := []struct {
		name    string
		args    args
		want    RDN
		wantErr bool
	}{
		{
			"TestCase:1 AttributeTypeAndValue",
			args{innerRDNSET{iatv1}},
			RDN{
				AttributeTypeAndValue{Type: CountryName, Value: AttributeValue{Encoding: PrintableString, Value: "a"}},
			},
			false,
		},
		{"TestCase:2 AttributeTypeAndValue",
			args{innerRDNSET{iatv1, iatv2}},
			RDN{
				AttributeTypeAndValue{Type: CountryName, Value: AttributeValue{Encoding: PrintableString, Value: "a"}},
				AttributeTypeAndValue{Type: CountryName, Value: AttributeValue{Encoding: PrintableString, Value: "aa"}},
			},
			false},
		{
			"TestCase:Broken AttributeTypeAndValue",
			args{innerRDNSET{iatv3}},
			RDN{},
			true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := convertToRdn(tt.args.irdn)
			if (err != nil) != tt.wantErr {
				t.Errorf("convertToRdn() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("convertToRdn() got = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_convertToDn(t *testing.T) {
	var r1 = asn1.RawValue{Tag: asn1.TagPrintableString, Bytes: decode("61"), FullBytes: decode("130161")}     //PrintableString a
	var r2 = asn1.RawValue{Tag: asn1.TagPrintableString, Bytes: decode("6161"), FullBytes: decode("13026161")} //PrintableString a

	var iatv1 = innerAttributeTypeAndValue{Type: asn1.ObjectIdentifier{2, 5, 4, 6}, Value: r1}
	var iatv2 = innerAttributeTypeAndValue{Type: asn1.ObjectIdentifier{2, 5, 4, 6}, Value: r2}
	var iatv3 = innerAttributeTypeAndValue{Type: asn1.ObjectIdentifier{9, 9, 9, 9}, Value: r1}

	var irv1 = innerRDNSET{iatv1}
	var irv2 = innerRDNSET{iatv2}
	var irv3 = innerRDNSET{iatv3}

	type args struct {
		idn innerDN
	}
	tests := []struct {
		name    string
		args    args
		want    DN
		wantErr bool
	}{
		{
			"TestCase:0 RDN",
			args{innerDN{}},
			DN{},
			false,
		},
		{
			"TestCase:1 RDN",
			args{innerDN{irv1}},
			DN{
				RDN{AttributeTypeAndValue{Type: CountryName, Value: AttributeValue{Encoding: PrintableString, Value: "a"}}},
			},
			false,
		},
		{
			"TestCase:2 RDN",
			args{innerDN{irv1, irv2}},
			DN{
				RDN{AttributeTypeAndValue{Type: CountryName, Value: AttributeValue{Encoding: PrintableString, Value: "a"}}},
				RDN{AttributeTypeAndValue{Type: CountryName, Value: AttributeValue{Encoding: PrintableString, Value: "aa"}}},
			},
			false,
		},
		{
			"TestCase:Broken RDN",
			args{innerDN{irv3}},
			DN{},
			true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := convertToDn(tt.args.idn)
			if (err != nil) != tt.wantErr {
				t.Errorf("convertToDn() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("convertToDn() got = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestParseDERDN(t *testing.T) {
	type args struct {
		dnBytes []byte
	}
	tests := []struct {
		name    string
		args    args
		wantDn  DN
		wantErr bool
	}{
		{"TestCase:C=JP,O=example,OU=Ext,OU=Dev+OU=Sales,CN=cn1", args{decode("3057310b3009060355040613024a503110300e060355040a0c076578616d706c65310c300a060355040b0c03457874311a300a060355040b0c03446576300c060355040b0c0553616c6573310c300a06035504030c03636e31")},
			DN{
				RDN{AttributeTypeAndValue{Type: CountryName, Value: AttributeValue{Encoding: PrintableString, Value: "JP"}}},
				RDN{AttributeTypeAndValue{Type: OrganizationName, Value: AttributeValue{Encoding: UTF8String, Value: "example"}}},
				RDN{AttributeTypeAndValue{Type: OrganizationalUnit, Value: AttributeValue{Encoding: UTF8String, Value: "Ext"}}},
				RDN{
					AttributeTypeAndValue{Type: OrganizationalUnit, Value: AttributeValue{Encoding: UTF8String, Value: "Dev"}},
					AttributeTypeAndValue{Type: OrganizationalUnit, Value: AttributeValue{Encoding: UTF8String, Value: "Sales"}},
				},
				RDN{AttributeTypeAndValue{Type: CommonName, Value: AttributeValue{Encoding: UTF8String, Value: "cn1"}}},
			},
			false},
		{"TestCase:Empty DN", args{decode("3000")}, DN{}, false},
		{"TestCase:C=JP(UTF8String))", args{decode("300d310b300906035504060c024a50")}, nil, true},
		{"TestCase:Broken DER DN", args{decode("13016161")}, nil, true},
		{"TestCase:CN=a(BMPString)", args{decode("300d310b300906035504031e020061")}, nil, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotDn, err := ParseDERDN(tt.args.dnBytes)
			if (err != nil) != tt.wantErr {
				t.Errorf("ParseDERDN() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(gotDn, tt.wantDn) {
				t.Errorf("ParseDERDN() gotDn = %v, want %v", gotDn, tt.wantDn)
			}
		})
	}
}

func TestReferAttributeTypeName(t *testing.T) {
	type args struct {
		oid asn1.ObjectIdentifier
	}
	tests := []struct {
		name    string
		args    args
		wantAtn AttributeType
		wantErr bool
	}{
		{"TestCase:CountryName", args{asn1.ObjectIdentifier{2, 5, 4, 6}}, CountryName, false},
		{"TestCase:OrganizationName", args{asn1.ObjectIdentifier{2, 5, 4, 10}}, OrganizationName, false},
		{"TestCase:OrganizationalUnit", args{asn1.ObjectIdentifier{2, 5, 4, 11}}, OrganizationalUnit, false},
		{"TestCase:DnQualifier", args{asn1.ObjectIdentifier{2, 5, 4, 46}}, DnQualifier, false},
		{"TestCase:StateOrProvinceName", args{asn1.ObjectIdentifier{2, 5, 4, 8}}, StateOrProvinceName, false},
		{"TestCase:CommonName", args{asn1.ObjectIdentifier{2, 5, 4, 3}}, CommonName, false},
		{"TestCase:SerialNumber", args{asn1.ObjectIdentifier{2, 5, 4, 5}}, SerialNumber, false},
		{"TestCase:LocalityName", args{asn1.ObjectIdentifier{2, 5, 4, 7}}, LocalityName, false},
		{"TestCase:Title", args{asn1.ObjectIdentifier{2, 5, 4, 12}}, Title, false},
		{"TestCase:Surname", args{asn1.ObjectIdentifier{2, 5, 4, 4}}, Surname, false},
		{"TestCase:GivenName", args{asn1.ObjectIdentifier{2, 5, 4, 42}}, GivenName, false},
		{"TestCase:Initials", args{asn1.ObjectIdentifier{2, 5, 4, 43}}, Initials, false},
		{"TestCase:Pseudonym", args{asn1.ObjectIdentifier{2, 5, 4, 65}}, Pseudonym, false},
		{"TestCase:GenerationQualifier", args{asn1.ObjectIdentifier{2, 5, 4, 44}}, GenerationQualifier, false},
		{"TestCase:ElectronicMailAddress", args{asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 1}}, ElectronicMailAddress, false},
		{"TestCase:DomainComponent", args{asn1.ObjectIdentifier{0, 9, 2342, 19200300, 100, 1, 25}}, DomainComponent, false},
		{"TestCase:Others", args{asn1.ObjectIdentifier{9, 9, 9, 9}}, 0, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotAtn, err := ReferAttributeTypeName(tt.args.oid)
			if (err != nil) != tt.wantErr {
				t.Errorf("ReferAttributeTypeName() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if gotAtn != tt.wantAtn {
				t.Errorf("ReferAttributeTypeName() gotAtn = %v, want %v", gotAtn, tt.wantAtn)
			}
		})
	}
}

func Test_convertToInnerAttributeTypeAndValue(t *testing.T) {
	var r1 = asn1.RawValue{Tag: asn1.TagPrintableString, FullBytes: decode("13024A50")}    //PrintableString JP
	var r2 = asn1.RawValue{Tag: asn1.TagUTF8String, FullBytes: decode("0C06E697A5E69CAC")} //UTF8String 日本
	var atv1 = AttributeValue{Encoding: PrintableString, Value: "JP"}
	var atnv1 = AttributeTypeAndValue{Type: CountryName, Value: atv1}
	var atv2 = AttributeValue{Encoding: 99, Value: "JP"}
	var atnv2 = AttributeTypeAndValue{Type: CountryName, Value: atv2}
	var atv3 = AttributeValue{Encoding: PrintableString, Value: "JP"}
	var atnv3 = AttributeTypeAndValue{Type: 9999, Value: atv3}
	var atv4 = AttributeValue{Encoding: UTF8String, Value: "日本"}
	var atnv4 = AttributeTypeAndValue{Type: CommonName, Value: atv4}
	type args struct {
		atv AttributeTypeAndValue
	}
	tests := []struct {
		name    string
		args    args
		want    innerAttributeTypeAndValue
		wantErr bool
	}{
		{"TestCase:CountryName PrintableString JP", args{atnv1}, innerAttributeTypeAndValue{Type: asn1.ObjectIdentifier{2, 5, 4, 6}, Value: r1}, false},
		{"TestCase:CommonName UTF8String 日本", args{atnv4}, innerAttributeTypeAndValue{Type: asn1.ObjectIdentifier{2, 5, 4, 3}, Value: r2}, false},
		{"TestCase:CountryName Unknown Encoding", args{atnv2}, innerAttributeTypeAndValue{}, true},
		{"TestCase:CountryName Unknown AttributeType", args{atnv3}, innerAttributeTypeAndValue{}, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := convertToInnerAttributeTypeAndValue(tt.args.atv)
			if (err != nil) != tt.wantErr {
				t.Errorf("convertToInnerAttributeTypeAndValue() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("convertToInnerAttributeTypeAndValue() got = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_convertToInnerRDNSET(t *testing.T) {
	var atv1 = AttributeTypeAndValue{Type: CommonName, Value: AttributeValue{Encoding: PrintableString, Value: "a"}}
	var rv1 = asn1.RawValue{Tag: asn1.TagPrintableString, FullBytes: decode("130161")} //PrintableString "a"
	var atv2 = AttributeTypeAndValue{Type: CommonName, Value: AttributeValue{Encoding: PrintableString, Value: "aa"}}
	var rv2 = asn1.RawValue{Tag: asn1.TagPrintableString, FullBytes: decode("13026161")} //PrintableString "aa"
	type args struct {
		rdn RDN
	}
	tests := []struct {
		name    string
		args    args
		want    innerRDNSET
		wantErr bool
	}{
		{"TestCase:1 AttributeTypeAndValue",
			args{RDN{atv1}},
			innerRDNSET{innerAttributeTypeAndValue{Type: asn1.ObjectIdentifier{2, 5, 4, 3}, Value: rv1}},
			false},
		{"TestCase:2 AttributeTypeAndValue",
			args{RDN{atv1, atv2}},
			innerRDNSET{
				innerAttributeTypeAndValue{Type: asn1.ObjectIdentifier{2, 5, 4, 3}, Value: rv1},
				innerAttributeTypeAndValue{Type: asn1.ObjectIdentifier{2, 5, 4, 3}, Value: rv2},
			},
			false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := convertToInnerRDNSET(tt.args.rdn)
			if (err != nil) != tt.wantErr {
				t.Errorf("convertToInnerRDNSET() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("convertToInnerRDNSET() got = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_convertToInnerDN(t *testing.T) {
	var atv1 = AttributeTypeAndValue{Type: CommonName, Value: AttributeValue{Encoding: PrintableString, Value: "a"}}
	var rv1 = asn1.RawValue{Tag: asn1.TagPrintableString, FullBytes: decode("130161")} //PrintableString "a"
	var rdn1 = RDN{atv1}
	var atv2 = AttributeTypeAndValue{Type: CommonName, Value: AttributeValue{Encoding: PrintableString, Value: "aa"}}
	var rv2 = asn1.RawValue{Tag: asn1.TagPrintableString, FullBytes: decode("13026161")} //PrintableString "a"
	var rdn2 = RDN{atv2}
	var atv3 = AttributeTypeAndValue{Type: 999, Value: AttributeValue{Encoding: PrintableString, Value: "aa"}}
	var rdn3 = RDN{atv3}
	type args struct {
		dn DN
	}
	tests := []struct {
		name    string
		args    args
		want    innerDN
		wantErr bool
	}{
		{"TestCase:0 RDN",
			args{DN{}},
			innerDN{},
			false},
		{"TestCase:1 RDN",
			args{DN{rdn1}},
			innerDN{innerRDNSET{innerAttributeTypeAndValue{Type: asn1.ObjectIdentifier{2, 5, 4, 3}, Value: rv1}}},
			false},
		{"TestCase:2 RDN",
			args{DN{rdn1, rdn2}},
			innerDN{
				innerRDNSET{innerAttributeTypeAndValue{Type: asn1.ObjectIdentifier{2, 5, 4, 3}, Value: rv1}},
				innerRDNSET{innerAttributeTypeAndValue{Type: asn1.ObjectIdentifier{2, 5, 4, 3}, Value: rv2}},
			},
			false},
		{"TestCase:Broken RDN", args{DN{rdn3}}, innerDN{}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := convertToInnerDN(tt.args.dn)
			if (err != nil) != tt.wantErr {
				t.Errorf("convertToInnerDN() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("convertToInnerDN() got = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestMarshalDN(t *testing.T) {
	var dn1 = DN{
		RDN{AttributeTypeAndValue{Type: CountryName, Value: AttributeValue{Encoding: PrintableString, Value: "JP"}}},
		RDN{AttributeTypeAndValue{Type: OrganizationName, Value: AttributeValue{Encoding: UTF8String, Value: "example"}}},
		RDN{AttributeTypeAndValue{Type: OrganizationalUnit, Value: AttributeValue{Encoding: UTF8String, Value: "Ext"}}},
		RDN{
			AttributeTypeAndValue{Type: OrganizationalUnit, Value: AttributeValue{Encoding: UTF8String, Value: "Dev"}},
			AttributeTypeAndValue{Type: OrganizationalUnit, Value: AttributeValue{Encoding: UTF8String, Value: "Sales"}},
		},
		RDN{
			AttributeTypeAndValue{Type: CommonName, Value: AttributeValue{Encoding: UTF8String, Value: "ex"}},
			AttributeTypeAndValue{Type: ElectronicMailAddress, Value: AttributeValue{Encoding: IA5String, Value: "ex@example.com"}}},
	}
	var dn2 = DN{
		RDN{AttributeTypeAndValue{Type: 999, Value: AttributeValue{Encoding: UTF8String, Value: "cn1"}}},
	}
	//C=JP,O=example,OU=Ext,OU=Dev+OU=Sales,CN=ex+E=ex@example.com
	var dnbytes1 = decode("3073310b3009060355040613024a503110300e060355040a0c076578616d706c65310c300a060355040b0c03457874311a300a060355040b0c03446576300c060355040b0c0553616c65733128300906035504030c026578301b06092a864886f70d010901160e6578406578616d706c652e636f6d")
	var dnbytes2 = decode("3000")

	type args struct {
		dn DN
	}

	tests := []struct {
		name        string
		args        args
		wantDnBytes []byte
		wantErr     bool
	}{
		{"TestCase:C=JP,O=example,OU=Ext,OU=Dev+OU=Sales,CN=ex+E=ex@example.com", args{dn1}, dnbytes1, false},
		{"TestCase:OU=a+OU=aa ", args{dn1}, dnbytes1, false},
		{"TestCase: Empty DN", args{DN{}}, dnbytes2, false},
		{"TestCase: Invalid AttributeType DN", args{dn2}, nil, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotDnBytes, err := MarshalDN(tt.args.dn)
			if (err != nil) != tt.wantErr {
				t.Errorf("MarshalDN() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(gotDnBytes, tt.wantDnBytes) {
				t.Errorf("MarshalDN() gotDnBytes = %v, want %v", gotDnBytes, tt.wantDnBytes)
			}
		})
	}
}

func TestMarshalDNToParseDERDn(t *testing.T) {
	var inDn = DN{
		RDN{
			AttributeTypeAndValue{Type: OrganizationalUnit, Value: AttributeValue{Encoding: UTF8String, Value: "a2"}},
			AttributeTypeAndValue{Type: OrganizationalUnit, Value: AttributeValue{Encoding: UTF8String, Value: "a1"}},
		},
	}
	//AttributeTypeAndValues of the dn are Binary sorted.
	var expectedDn = DN{
		RDN{
			AttributeTypeAndValue{Type: OrganizationalUnit, Value: AttributeValue{Encoding: UTF8String, Value: "a1"}},
			AttributeTypeAndValue{Type: OrganizationalUnit, Value: AttributeValue{Encoding: UTF8String, Value: "a2"}},
		},
	}
	marshaledDn, _ := MarshalDN(inDn)
	parsedDn, _ := ParseDERDN(marshaledDn)

	if !reflect.DeepEqual(parsedDn, expectedDn) {
		t.Errorf("ReParseDERDn = %v, want %v", parsedDn, expectedDn)
	}

}

func Test_isValidAttributeType(t *testing.T) {
	type args struct {
		at AttributeType
	}
	tests := []struct {
		name        string
		args        args
		wantIsValid bool
		wantErr     bool
	}{
		{"TestCase: CountryName", args{CountryName}, true, false},
		{"TestCase: OrganizationName", args{OrganizationName}, true, false},
		{"TestCase: OrganizationalUnit", args{OrganizationalUnit}, true, false},
		{"TestCase: DnQualifier", args{DnQualifier}, true, false},
		{"TestCase: StateOrProvinceName", args{StateOrProvinceName}, true, false},
		{"TestCase: CommonName", args{CommonName}, true, false},
		{"TestCase: SerialNumber", args{SerialNumber}, true, false},
		{"TestCase: LocalityName", args{LocalityName}, true, false},
		{"TestCase: Title", args{Title}, true, false},
		{"TestCase: Surname", args{Surname}, true, false},
		{"TestCase: GivenName", args{GivenName}, true, false},
		{"TestCase: Initials", args{Initials}, true, false},
		{"TestCase: Pseudonym", args{Pseudonym}, true, false},
		{"TestCase: GenerationQualifier", args{GenerationQualifier}, true, false},
		{"TestCase: ElectronicMailAddress", args{ElectronicMailAddress}, true, false},
		{"TestCase: DomainComponent", args{DomainComponent}, true, false},
		{"TestCase: the other", args{999}, false, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotIsValid, err := isValidAttributeType(tt.args.at)
			if (err != nil) != tt.wantErr {
				t.Errorf("isValidAttributeType() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if gotIsValid != tt.wantIsValid {
				t.Errorf("isValidAttributeType() gotIsValid = %v, want %v", gotIsValid, tt.wantIsValid)
			}
		})
	}
}

func Test_isValidAttributeTypeAndAttributeValueComb(t *testing.T) {
	type args struct {
		at AttributeType
		av AttributeValue
	}
	tests := []struct {
		name        string
		args        args
		wantIsValid bool
		wantErr     bool
	}{
		{"TestCase: CountryName, PrintableString", args{CountryName, AttributeValue{Encoding: PrintableString}}, true, false},
		{"TestCase: CountryName, the other", args{CountryName, AttributeValue{Encoding: UTF8String}}, false, true},

		{"TestCase: OrganizationName, PrintableString", args{OrganizationName, AttributeValue{Encoding: PrintableString}}, true, false},
		{"TestCase: OrganizationName, UTF8String", args{OrganizationName, AttributeValue{Encoding: UTF8String}}, true, false},
		{"TestCase: OrganizationName, the other", args{OrganizationName, AttributeValue{Encoding: IA5String}}, false, true},

		{"TestCase: OrganizationalUnit, PrintableString", args{OrganizationalUnit, AttributeValue{Encoding: PrintableString}}, true, false},
		{"TestCase: OrganizationalUnit, UTF8String", args{OrganizationalUnit, AttributeValue{Encoding: UTF8String}}, true, false},
		{"TestCase: OrganizationalUnit, the other", args{OrganizationalUnit, AttributeValue{Encoding: IA5String}}, false, true},

		{"TestCase: DnQualifier, PrintableString", args{DnQualifier, AttributeValue{Encoding: PrintableString}}, true, false},
		{"TestCase: DnQualifier, the other", args{DnQualifier, AttributeValue{Encoding: UTF8String}}, false, true},

		{"TestCase: StateOrProvinceName, PrintableString", args{StateOrProvinceName, AttributeValue{Encoding: PrintableString}}, true, false},
		{"TestCase: StateOrProvinceName, UTF8String", args{StateOrProvinceName, AttributeValue{Encoding: UTF8String}}, true, false},
		{"TestCase: StateOrProvinceName, the other", args{StateOrProvinceName, AttributeValue{Encoding: IA5String}}, false, true},

		{"TestCase: CommonNam, PrintableString", args{CommonName, AttributeValue{Encoding: PrintableString}}, true, false},
		{"TestCase: CommonName, UTF8String", args{CommonName, AttributeValue{Encoding: UTF8String}}, true, false},
		{"TestCase: CommonName, the other", args{CommonName, AttributeValue{Encoding: IA5String}}, false, true},

		{"TestCase: SerialNumber, PrintableString", args{SerialNumber, AttributeValue{Encoding: PrintableString}}, true, false},
		{"TestCase: SerialNumber, the other", args{SerialNumber, AttributeValue{Encoding: UTF8String}}, false, true},

		{"TestCase: LocalityName, PrintableString", args{LocalityName, AttributeValue{Encoding: PrintableString}}, true, false},
		{"TestCase: LocalityName, UTF8String", args{LocalityName, AttributeValue{Encoding: UTF8String}}, true, false},
		{"TestCase: LocalityName, the other", args{LocalityName, AttributeValue{Encoding: IA5String}}, false, true},

		{"TestCase: Title, PrintableString", args{Title, AttributeValue{Encoding: PrintableString}}, true, false},
		{"TestCase: Title, UTF8String", args{Title, AttributeValue{Encoding: UTF8String}}, true, false},
		{"TestCase: Title, the other", args{Title, AttributeValue{Encoding: IA5String}}, false, true},

		{"TestCase: Surname, PrintableString", args{Surname, AttributeValue{Encoding: PrintableString}}, true, false},
		{"TestCase: Surname, UTF8String", args{Surname, AttributeValue{Encoding: UTF8String}}, true, false},
		{"TestCase: Surname, the other", args{Surname, AttributeValue{Encoding: IA5String}}, false, true},

		{"TestCase: GivenName, PrintableString", args{GivenName, AttributeValue{Encoding: PrintableString}}, true, false},
		{"TestCase: GivenName, UTF8String", args{GivenName, AttributeValue{Encoding: UTF8String}}, true, false},
		{"TestCase: GivenName, the other", args{GivenName, AttributeValue{Encoding: IA5String}}, false, true},

		{"TestCase: Initials, PrintableString", args{Initials, AttributeValue{Encoding: PrintableString}}, true, false},
		{"TestCase: Initials, UTF8String", args{Initials, AttributeValue{Encoding: UTF8String}}, true, false},
		{"TestCase: Initials, the other", args{Initials, AttributeValue{Encoding: IA5String}}, false, true},

		{"TestCase: Pseudonym, PrintableString", args{Pseudonym, AttributeValue{Encoding: PrintableString}}, true, false},
		{"TestCase: Pseudonym, UTF8String", args{Pseudonym, AttributeValue{Encoding: UTF8String}}, true, false},
		{"TestCase: Pseudonym, the other", args{Pseudonym, AttributeValue{Encoding: IA5String}}, false, true},

		{"TestCase: GenerationQualifier, PrintableString", args{GenerationQualifier, AttributeValue{Encoding: PrintableString}}, true, false},
		{"TestCase: GenerationQualifier, UTF8String", args{GenerationQualifier, AttributeValue{Encoding: UTF8String}}, true, false},
		{"TestCase: GenerationQualifier, the other", args{GenerationQualifier, AttributeValue{Encoding: IA5String}}, false, true},

		{"TestCase: ElectronicMailAddress, IA5String", args{ElectronicMailAddress, AttributeValue{Encoding: IA5String}}, true, false},
		{"TestCase: ElectronicMailAddress, the other", args{ElectronicMailAddress, AttributeValue{Encoding: UTF8String}}, false, true},

		{"TestCase: DomainComponent, IA5String", args{DomainComponent, AttributeValue{Encoding: IA5String}}, true, false},
		{"TestCase: DomainComponent, the other", args{DomainComponent, AttributeValue{Encoding: UTF8String}}, false, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotIsValid, err := isValidAttributeTypeAndAttributeValueComb(tt.args.at, tt.args.av)
			if (err != nil) != tt.wantErr {
				t.Errorf("isValidAttributeTypeAndAttributeValueComb() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if gotIsValid != tt.wantIsValid {
				t.Errorf("isValidAttributeTypeAndAttributeValueComb() gotIsValid = %v, want %v", gotIsValid, tt.wantIsValid)
			}
		})
	}
}

func Test_isPrintableStringEncoding(t *testing.T) {
	type args struct {
		e Encoding
	}
	tests := []struct {
		name   string
		args   args
		wantOk bool
	}{
		{"TestCase: PrintableString", args{PrintableString}, true},
		{"TestCase: The other", args{UTF8String}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if gotOk := isPrintableStringEncoding(tt.args.e); gotOk != tt.wantOk {
				t.Errorf("isPrintableStringEncoding() = %v, want %v", gotOk, tt.wantOk)
			}
		})
	}
}

func Test_isIA5StringEncoding(t *testing.T) {
	type args struct {
		e Encoding
	}
	tests := []struct {
		name   string
		args   args
		wantOk bool
	}{
		{"TestCase: IA5String", args{IA5String}, true},
		{"TestCase: The other", args{UTF8String}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if gotOk := isIA5StringEncoding(tt.args.e); gotOk != tt.wantOk {
				t.Errorf("isIA5StringEncoding() = %v, want %v", gotOk, tt.wantOk)
			}
		})
	}
}

func Test_isPrintableStringOrUTF8StringEncoding(t *testing.T) {
	type args struct {
		e Encoding
	}
	tests := []struct {
		name   string
		args   args
		wantOk bool
	}{
		{"TestCase: PrintableString", args{PrintableString}, true},
		{"TestCase: UTF8String", args{UTF8String}, true},
		{"TestCase: The other", args{IA5String}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if gotOk := isPrintableStringOrUTF8StringEncoding(tt.args.e); gotOk != tt.wantOk {
				t.Errorf("isPrintableStringOrUTF8StringEncoding() = %v, want %v", gotOk, tt.wantOk)
			}
		})
	}
}

func Test_isValidAttributeValueEncoding(t *testing.T) {
	type args struct {
		av AttributeValue
	}
	tests := []struct {
		name        string
		args        args
		wantIsValid bool
		wantErr     bool
	}{
		{"TestCase: PrintableString", args{AttributeValue{Encoding: PrintableString}}, true, false},
		{"TestCase: UTF8String", args{AttributeValue{Encoding: UTF8String}}, true, false},
		{"TestCase: IA5String", args{AttributeValue{Encoding: IA5String}}, true, false},
		{"TestCase: The other", args{AttributeValue{Encoding: 999}}, false, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotIsValid, err := isValidAttributeValueEncoding(tt.args.av)
			if (err != nil) != tt.wantErr {
				t.Errorf("isValidAttributeValueEncoding() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if gotIsValid != tt.wantIsValid {
				t.Errorf("isValidAttributeValueEncoding() gotIsValid = %v, want %v", gotIsValid, tt.wantIsValid)
			}
		})
	}
}

func Test_isValidAttributeTypeAndValue(t *testing.T) {
	type args struct {
		atv AttributeTypeAndValue
	}
	tests := []struct {
		name        string
		args        args
		wantIsValid bool
		wantErr     bool
	}{
		{"TestCase: CountryName, PrintableString", args{AttributeTypeAndValue{Type: CountryName, Value: AttributeValue{Encoding: PrintableString}}}, true, false},
		{"TestCase: The other, PrintableString", args{AttributeTypeAndValue{Type: 999, Value: AttributeValue{Encoding: PrintableString}}}, false, true},
		{"TestCase: CountryName, The other", args{AttributeTypeAndValue{Type: CountryName, Value: AttributeValue{Encoding: 999}}}, false, true},
		{"TestCase: CountryName, UTF8String", args{AttributeTypeAndValue{Type: CountryName, Value: AttributeValue{Encoding: UTF8String}}}, false, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotIsValid, err := isValidAttributeTypeAndValue(tt.args.atv)
			if (err != nil) != tt.wantErr {
				t.Errorf("isValidAttributeTypeAndValue() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if gotIsValid != tt.wantIsValid {
				t.Errorf("isValidAttributeTypeAndValue() gotIsValid = %v, want %v", gotIsValid, tt.wantIsValid)
			}
		})
	}
}

func Test_isValidRDN(t *testing.T) {
	atv1 := AttributeTypeAndValue{Type: CountryName, Value: AttributeValue{Encoding: PrintableString}}
	atv2 := AttributeTypeAndValue{Type: CommonName, Value: AttributeValue{Encoding: UTF8String}}
	atv3 := AttributeTypeAndValue{Type: CountryName, Value: AttributeValue{Encoding: UTF8String}}
	atv4 := AttributeTypeAndValue{Type: ElectronicMailAddress, Value: AttributeValue{Encoding: UTF8String}}
	type args struct {
		r RDN
	}
	tests := []struct {
		name        string
		args        args
		wantIsValid bool
		wantErr     bool
	}{
		{"TestCase: 0 AttributeTypeAndValue element", args{RDN{}}, false, true},
		{"TestCase: 1 AttributeTypeAndValue element", args{RDN{atv1}}, true, false},
		{"TestCase: 2 AttributeTypeAndValue element", args{RDN{atv1, atv2}}, true, false},
		{"TestCase: 1 invalid AttributeTypeAndValue element", args{RDN{atv3}}, false, true},
		{"TestCase: 2 invalid AttributeTypeAndValue element", args{RDN{atv3, atv4}}, false, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotIsValid, err := isValidRDN(tt.args.r)
			if (err != nil) != tt.wantErr {
				t.Errorf("isValidRDN() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if gotIsValid != tt.wantIsValid {
				t.Errorf("isValidRDN() gotIsValid = %v, want %v", gotIsValid, tt.wantIsValid)
			}
		})
	}
}

func Test_isValidDN(t *testing.T) {
	atv1 := AttributeTypeAndValue{Type: CountryName, Value: AttributeValue{Encoding: PrintableString}}
	atv2 := AttributeTypeAndValue{Type: CommonName, Value: AttributeValue{Encoding: UTF8String}}
	atv3 := AttributeTypeAndValue{Type: CountryName, Value: AttributeValue{Encoding: UTF8String}}
	atv4 := AttributeTypeAndValue{Type: ElectronicMailAddress, Value: AttributeValue{Encoding: UTF8String}}
	rdn1 := RDN{atv1, atv2}
	rdn2 := RDN{atv2}
	rdn3 := RDN{atv1, atv3}
	rdn4 := RDN{atv4}

	type args struct {
		d DN
	}
	tests := []struct {
		name        string
		args        args
		wantIsValid bool
		wantErr     bool
	}{
		{"TestCase: 0 RDN element", args{DN{}}, true, false},
		{"TestCase: 1 RDN element", args{DN{rdn1}}, true, false},
		{"TestCase: 2 RDN element", args{DN{rdn1, rdn2}}, true, false},
		{"TestCase: 1 invalid RDN element", args{DN{rdn3}}, false, true},
		{"TestCase: 2 invalid RDN element", args{DN{rdn3, rdn4}}, false, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotIsValid, err := isValidDN(tt.args.d)
			if (err != nil) != tt.wantErr {
				t.Errorf("isValidDN() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if gotIsValid != tt.wantIsValid {
				t.Errorf("isValidDN() gotIsValid = %v, want %v", gotIsValid, tt.wantIsValid)
			}
		})
	}
}

func TestDN_RetrieveRDN(t *testing.T) {
	atv1 := AttributeTypeAndValue{Type: CountryName, Value: AttributeValue{Encoding: PrintableString}}
	atv2 := AttributeTypeAndValue{Type: CommonName, Value: AttributeValue{Encoding: UTF8String}}
	type args struct {
		index int
	}
	tests := []struct {
		name    string
		d       DN
		args    args
		wantRdn RDN
		wantErr bool
	}{
		{"TestCase: 0 RDN element index 0", DN{}, args{0}, RDN{}, true},
		{"TestCase: 1 RDN element index 0", DN{RDN{atv1}}, args{0}, RDN{atv1}, false},
		{"TestCase: 1 RDN element index 1", DN{RDN{atv1}}, args{1}, RDN{}, true},
		{"TestCase: 2 RDN element index -1", DN{RDN{atv1}, RDN{atv2}}, args{-1}, RDN{}, true},
		{"TestCase: 2 RDN element index 0", DN{RDN{atv1}, RDN{atv2}}, args{0}, RDN{atv1}, false},
		{"TestCase: 2 RDN element index 1", DN{RDN{atv1}, RDN{atv2}}, args{1}, RDN{atv2}, false},
		{"TestCase: 2 RDN element index 2", DN{RDN{atv1}, RDN{atv2}}, args{2}, RDN{}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotRdn, err := tt.d.RetrieveRDN(tt.args.index)
			if (err != nil) != tt.wantErr {
				t.Errorf("RetrieveRDN() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(gotRdn, tt.wantRdn) {
				t.Errorf("RetrieveRDN() gotRdn = %v, want %v", gotRdn, tt.wantRdn)
			}
		})
	}
}

func TestDN_RetrieveRDNsByAttributeTypes(t *testing.T) {
	atv1 := AttributeTypeAndValue{Type: CountryName, Value: AttributeValue{Encoding: PrintableString}}
	atv2 := AttributeTypeAndValue{Type: CommonName, Value: AttributeValue{Encoding: UTF8String}}
	atv3 := AttributeTypeAndValue{Type: OrganizationName, Value: AttributeValue{Encoding: UTF8String}}
	atv4 := AttributeTypeAndValue{Type: OrganizationalUnit, Value: AttributeValue{Encoding: UTF8String}}
	type args struct {
		ats []AttributeType
	}
	tests := []struct {
		name     string
		d        DN
		args     args
		wantRdns []RDN
	}{
		{"TestCase: DN has 0 RDN, 0 AttributeType, not matched", DN{}, args{[]AttributeType{}}, []RDN{}},
		{"TestCase: DN has 0 RDN, 1 AttributeType, not matched", DN{}, args{[]AttributeType{CountryName}}, []RDN{}},
		{"TestCase: DN has 1 RDN, RDN has 1 Attribute , 0 AttributeType, not matched", DN{RDN{atv1}}, args{[]AttributeType{}}, []RDN{}},
		{"TestCase: DN has 1 RDN, RDN has 1 Attribute , 1 AttributeType, matched", DN{RDN{atv1}}, args{[]AttributeType{CountryName}}, []RDN{RDN{atv1}}},
		{"TestCase: DN has 1 RDN, RDN has 1 Attribute , 1 AttributeType, not matched", DN{RDN{atv1}}, args{[]AttributeType{OrganizationName}}, []RDN{}},
		{"TestCase: DN has 2 RDN, RDN has 1 Attribute , 1 AttributeType, 1 matched", DN{RDN{atv1}, RDN{atv2}}, args{[]AttributeType{CountryName}}, []RDN{RDN{atv1}}},
		{"TestCase: DN has 2 RDN, RDN has 1 Attribute , 1 AttributeType, 2 matched", DN{RDN{atv1}, RDN{atv1}}, args{[]AttributeType{CountryName}}, []RDN{RDN{atv1}, RDN{atv1}}},
		{"TestCase: DN has 2 RDN, RDN has 1 Attribute , 2 AttributeType, 1 matched", DN{RDN{atv1, atv2}}, args{[]AttributeType{CommonName, CountryName}}, []RDN{RDN{atv1, atv2}}},
		{"TestCase: DN has 2 RDN, RDN has 1 Attribute , 2 AttributeType(Reverse Order), 1 matched", DN{RDN{atv1, atv2}}, args{[]AttributeType{CountryName, CommonName}}, []RDN{RDN{atv1, atv2}}},
		{"TestCase: DN has 2 RDN, RDN has 2 Attribute , 2 AttributeType, 2 matched", DN{RDN{atv1, atv2}, RDN{atv1, atv2}}, args{[]AttributeType{CountryName, CommonName}}, []RDN{RDN{atv1, atv2}, RDN{atv1, atv2}}},
		{"TestCase: DN has 2 RDN, RDN has 2 Attribute , 2 AttributeType, 1 matched", DN{RDN{atv1, atv2}, RDN{atv3, atv4}}, args{[]AttributeType{CountryName, CommonName}}, []RDN{RDN{atv1, atv2}}},
		{"TestCase: DN has 2 RDN, RDN has 2 Attribute , 2 AttributeType, not matched", DN{RDN{atv1, atv2}, RDN{atv3, atv4}}, args{[]AttributeType{OrganizationName, CommonName}}, []RDN{}},
		{"TestCase: DN has 2 RDN, RDN has 2 Attribute , 3 AttributeType, not matched", DN{RDN{atv1, atv2}, RDN{atv3, atv4}}, args{[]AttributeType{CountryName, OrganizationName, CommonName}}, []RDN{}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if gotRdns := tt.d.RetrieveRDNsByAttributeTypes(tt.args.ats); !reflect.DeepEqual(gotRdns, tt.wantRdns) {
				t.Errorf("RetrieveRDNsByAttributeTypes() = %v, want %v", gotRdns, tt.wantRdns)
			}
		})
	}
}

func Test_removeAttributeTypeAndValue(t *testing.T) {
	atv1 := AttributeTypeAndValue{Type: CountryName, Value: AttributeValue{Encoding: PrintableString}}
	atv2 := AttributeTypeAndValue{Type: CommonName, Value: AttributeValue{Encoding: UTF8String}}
	atv3 := AttributeTypeAndValue{Type: OrganizationName, Value: AttributeValue{Encoding: UTF8String}}
	type args struct {
		index int
		r     RDN
	}
	tests := []struct {
		name     string
		args     args
		wantRest RDN
	}{
		{"TestCase: 1 Attributes index 0", args{0, RDN{atv1}}, RDN{}},
		{"TestCase: 2 Attributes index 0", args{0, RDN{atv1, atv2}}, RDN{atv2}},
		{"TestCase: 2 Attributes index 1", args{1, RDN{atv1, atv2}}, RDN{atv1}},
		{"TestCase: 3 Attributes index 0", args{0, RDN{atv1, atv2, atv3}}, RDN{atv2, atv3}},
		{"TestCase: 3 Attributes index 1", args{1, RDN{atv1, atv2, atv3}}, RDN{atv1, atv3}},
		{"TestCase: 3 Attributes index 2", args{2, RDN{atv1, atv2, atv3}}, RDN{atv1, atv2}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if gotRest := removeAttributeTypeAndValue(tt.args.index, tt.args.r); !reflect.DeepEqual(gotRest, tt.wantRest) {
				t.Errorf("removeAttributeTypeAndValue() = %v, want %v", gotRest, tt.wantRest)
			}
		})
	}
}

func Test_isMatchedRDN(t *testing.T) {
	atv1 := AttributeTypeAndValue{Type: CountryName, Value: AttributeValue{Encoding: PrintableString}}
	atv2 := AttributeTypeAndValue{Type: CommonName, Value: AttributeValue{Encoding: UTF8String}}
	atv3 := AttributeTypeAndValue{Type: OrganizationName, Value: AttributeValue{Encoding: UTF8String}}
	type args struct {
		r   RDN
		ats []AttributeType
	}
	tests := []struct {
		name          string
		args          args
		wantIsMatched bool
	}{
		{"TestCase: 1 Attributes matched", args{RDN{atv1}, []AttributeType{CountryName}}, true},
		{"TestCase: 2 Attributes matched", args{RDN{atv1, atv2}, []AttributeType{CountryName, CommonName}}, true},
		{"TestCase: 2 Attributes(Revers order) matched", args{RDN{atv1, atv2}, []AttributeType{CommonName, CountryName}}, true},
		{"TestCase: 3 Attributes not matched", args{RDN{atv1, atv2, atv3}, []AttributeType{CommonName, CountryName, CommonName}}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if gotIsMatched := isMatchedRDN(tt.args.r, tt.args.ats); gotIsMatched != tt.wantIsMatched {
				t.Errorf("isMatchedRDN() = %v, want %v", gotIsMatched, tt.wantIsMatched)
			}
		})
	}
}

func Test_findMatchedAttributeTypeIndex(t *testing.T) {
	atv1 := AttributeTypeAndValue{Type: CountryName, Value: AttributeValue{Encoding: PrintableString}}
	atv2 := AttributeTypeAndValue{Type: CommonName, Value: AttributeValue{Encoding: UTF8String}}
	atv3 := AttributeTypeAndValue{Type: OrganizationName, Value: AttributeValue{Encoding: UTF8String}}
	type args struct {
		r  RDN
		at AttributeType
	}
	tests := []struct {
		name      string
		args      args
		wantIndex int
	}{
		{"TestCase: 0 Attributes  not matched", args{RDN{}, CountryName}, -1},
		{"TestCase: 3 Attributes  matched", args{RDN{atv1, atv2, atv3}, CountryName}, 0},
		{"TestCase: 3 Attributes  matched", args{RDN{atv1, atv2, atv3}, CommonName}, 1},
		{"TestCase: 3 Attributes  matched", args{RDN{atv1, atv2, atv3}, OrganizationName}, 2},
		{"TestCase: 3 Attributes  matched", args{RDN{atv1, atv2, atv3}, OrganizationalUnit}, -1},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if gotIndex := findMatchedAttributeTypeIndex(tt.args.r, tt.args.at); gotIndex != tt.wantIndex {
				t.Errorf("findMatchedAttributeTypeIndex() = %v, want %v", gotIndex, tt.wantIndex)
			}
		})
	}
}

func Test_needEscaping(t *testing.T) {
	type args struct {
		r rune
	}
	tests := []struct {
		name string
		args args
		want bool
	}{
		{"TestCase: U+0022", args{rune('\U00000022')}, true},
		{"TestCase: U+002B", args{rune('\U0000002B')}, true},
		{"TestCase: U+002C", args{rune('\U0000002C')}, true},
		{"TestCase: U+003B", args{rune('\U0000003B')}, true},
		{"TestCase: U+003C", args{rune('\U0000003C')}, true},
		{"TestCase: U+003E", args{rune('\U0000003E')}, true},
		{"TestCase: U+005C", args{rune('\U0000005C')}, true},
		{"TestCase: U+0000", args{rune('\U00000000')}, true},
		{"TestCase: A ", args{rune('\U00000041')}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := needEscaping(tt.args.r); got != tt.want {
				t.Errorf("needEscaping() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_escapeAttributeValue(t *testing.T) {
	type args struct {
		s string
	}
	tests := []struct {
		name string
		args args
		want string
	}{
		{"TestCase: AAA", args{"AAA"}, "AAA"},
		{"TestCase:  AAA", args{" AAA"}, "\\ AAA"},
		{"TestCase: #AAA", args{"#AAA"}, "\\#AAA"},
		{"TestCase:  AAA#", args{" AAA"}, "\\ AAA"},
		{"TestCase: #AAA ", args{"#AAA "}, "\\#AAA\\ "},
		{"TestCase:  AAA ", args{" AAA "}, "\\ AAA\\ "},
		{"TestCase:  A A A ", args{" A A A "}, "\\ A A A\\ "},
		{"TestCase: あ い う", args{" あ い う "}, "\\ あ い う\\ "},
		{"TestCase: あ(U+0022)い+う,え;お ", args{" あ\"い+う,え;お "}, "\\ あ\\\"い\\+う\\,え\\;お\\ "},
		{"TestCase: あ(U+003C)い(U+003E)う(U+005C)え ", args{" あ<い>う\\え "}, "\\ あ\\<い\\>う\\\\え\\ "},
		{"TestCase: James (U+0022)Jim(U+0022), III", args{"James \"Jim\" Smith, III"}, "James \\\"Jim\\\" Smith\\, III"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := escapeAttributeValue(tt.args.s); got != tt.want {
				t.Errorf("escapeAttributeValue() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestAttributeValue_ToRFC4514FormatString(t *testing.T) {
	type fields struct {
		Encoding Encoding
		Value    string
	}
	tests := []struct {
		name   string
		fields fields
		want   string
	}{
		{"TestCase: AAA", fields{2, "AAA"}, "AAA"},
		{"TestCase:  AAA", fields{2, " AAA"}, "\\ AAA"},
		{"TestCase: #AAA", fields{2, "#AAA"}, "\\#AAA"},
		{"TestCase:  AAA#", fields{2, " AAA"}, "\\ AAA"},
		{"TestCase: #AAA ", fields{2, "#AAA "}, "\\#AAA\\ "},
		{"TestCase:  AAA ", fields{2, " AAA "}, "\\ AAA\\ "},
		{"TestCase:  A A A ", fields{2, " A A A "}, "\\ A A A\\ "},
		{"TestCase: あ い う", fields{2, " あ い う "}, "\\ あ い う\\ "},
		{"TestCase: あ(U+0022)い+う,え;お ", fields{2, " あ\"い+う,え;お "}, "\\ あ\\\"い\\+う\\,え\\;お\\ "},
		{"TestCase: あ(U+003C)い(U+003E)う(U+005C)え ", fields{2, " あ<い>う\\え "}, "\\ あ\\<い\\>う\\\\え\\ "},
		{"TestCase: James (U+0022)Jim(U+0022) Smith, III", fields{2, "James \"Jim\" Smith, III"}, "James \\\"Jim\\\" Smith\\, III"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			av := AttributeValue{
				Encoding: tt.fields.Encoding,
				Value:    tt.fields.Value,
			}
			if got := av.ToRFC4514FormatString(); got != tt.want {
				t.Errorf("ToRFC4514FormatString() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestAttributeValue_String(t *testing.T) {
	type fields struct {
		Encoding Encoding
		Value    string
	}
	tests := []struct {
		name   string
		fields fields
		want   string
	}{
		{"TestCase: AAA", fields{2, "AAA"}, "AAA"},
		{"TestCase:  AAA", fields{2, " AAA"}, " AAA"},
		{"TestCase: #AAA", fields{2, "#AAA"}, "#AAA"},
		{"TestCase:  AAA#", fields{2, " AAA#"}, " AAA#"},
		{"TestCase: #AAA ", fields{2, "#AAA "}, "#AAA "},
		{"TestCase:  AAA ", fields{2, " AAA "}, " AAA "},
		{"TestCase:  A A A ", fields{2, " A A A "}, " A A A "},
		{"TestCase: あ い う", fields{2, " あ い う "}, " あ い う "},
		{"TestCase: あ(U+0022)い+う,え;お ", fields{2, " あ\"い+う,え;お "}, " あ\"い+う,え;お "},
		{"TestCase: あ(U+003C)い(U+003E)う(U+005C)え ", fields{2, " あ<い>う\\え "}, " あ<い>う\\え "},
		{"TestCase: James (U+0022)Jim(U+0022) Smith, III", fields{2, "James \"Jim\" Smith, III"}, "James \"Jim\" Smith, III"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			av := AttributeValue{
				Encoding: tt.fields.Encoding,
				Value:    tt.fields.Value,
			}
			if got := av.String(); got != tt.want {
				t.Errorf("String() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestAttributeTypeAndValue_ToRFC4514FormatString(t *testing.T) {
	type fields struct {
		Type  AttributeType
		Value AttributeValue
	}
	tests := []struct {
		name   string
		fields fields
		want   string
	}{
		{"TestCase: OrganizationName AAA", fields{OrganizationName, AttributeValue{UTF8String, "AAA"}}, "O=AAA"},
		{"TestCase: DnQualifier AAA", fields{DnQualifier, AttributeValue{UTF8String, "AAA"}}, "DNQUALIFIER=AAA"},
		{"TestCase: LocalityName  AAA", fields{LocalityName, AttributeValue{UTF8String, " AAA"}}, "L=\\ AAA"},
		{"TestCase: CommonName James (U+0022)Jim(U+0022) Smith, III", fields{CommonName, AttributeValue{UTF8String, "James \"Jim\" Smith, III"}}, "CN=James \\\"Jim\\\" Smith\\, III"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			atv := AttributeTypeAndValue{
				Type:  tt.fields.Type,
				Value: tt.fields.Value,
			}
			if got := atv.ToRFC4514FormatString(); got != tt.want {
				t.Errorf("ToRFC4514FormatString() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestAttributeTypeAndValue_String(t *testing.T) {
	type fields struct {
		Type  AttributeType
		Value AttributeValue
	}
	tests := []struct {
		name   string
		fields fields
		want   string
	}{
		{"TestCase: OrganizationName AAA", fields{OrganizationName, AttributeValue{UTF8String, "AAA"}}, "O=AAA"},
		{"TestCase: DnQualifier AAA", fields{DnQualifier, AttributeValue{UTF8String, "AAA"}}, "DNQUALIFIER=AAA"},
		{"TestCase: LocalityName  AAA", fields{LocalityName, AttributeValue{UTF8String, " AAA"}}, "L= AAA"},
		{"TestCase: CommonName James (U+0022)Jim(U+0022) Smith, III", fields{CommonName, AttributeValue{UTF8String, "James \"Jim\" Smith, III"}}, "CN=James \"Jim\" Smith, III"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			atv := AttributeTypeAndValue{
				Type:  tt.fields.Type,
				Value: tt.fields.Value,
			}
			if got := atv.String(); got != tt.want {
				t.Errorf("String() = %v, want %v", got, tt.want)
			}
		})
	}
}
