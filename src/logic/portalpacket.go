package logic

import (
	"net"
	"bytes"
	"encoding/binary"
	"crypto/md5"
	"io"
	"fmt"
)

//packet type: REQ/RSP
const (
	PACKETTYPE_REQ uint = 1 //request packet
	PACKETTYPE_RSP uint = 2 //response packet
)

const (
	DEF_PORTAL_VERSION1 = 1
	DEF_PORTAL_VERSION2 = 2
)

//portal request type
const (
	PACKETTYPE_REQCHALLENGE	= 0x01
	PACKETTYPE_ACKCHALLENGE	= 0x02
	PACKETTYPE_REQAUTH	= 0x03
	PACKETTYPE_ACKAUTH	= 0x04
	PACKETTYPE_REQLOGOUT	= 0x05
	PACKETTYPE_ACKLOGOUT	= 0x06
	PACKETTYPE_AFFACKAUTH	= 0x07
	PACKETTYPE_NTFLOGOUT	= 0x08
	PACKETTYPE_REQINFO	= 0x09
	PACKETTYPE_ACKINFO	= 0x0a
)

//portal authen mode: PAP/CHAP
const (
	AUTHMODE_CHAP		uint = 0x00
	AUTHMODE_PAP		uint = 0x01
)

//length definition for all fields
const (
	PP_VERSION_LEN 	     int = 1
	PP_TYPE_LEN 	     int = 1
	PP_AUTHMODE_LEN      int = 1
	PP_RSVD_LEN 	     int = 1
	PP_SERIALNO_LEN      int = 2
	PP_REQID_LEN	     int = 2
	PP_USERIP_LEN	     int = 4
	PP_USERPORT_LEN	     int = 2
	PP_ERRCODE_LEN	     int = 1
	PP_ATTRNUM_LEN	     int = 1
	PP_AUTHENTICATOR_LEN int = 16
)

//offset definition for all fields
const (
	PP_OFF_VERSION		int = 0
	PP_OFF_TYPE		int = 1
	PP_OFF_AUTHMODE		int = 2
	PP_OFF_RSVD		int = 3
	PP_OFF_SERIALNO		int = 4
	PP_OFF_REQID		int = 6
	PP_OFF_USERIP		int = 8
	PP_OFF_USERPORT		int = 12
	PP_OFF_ERRCODE		int = 14
	PP_OFF_ATTRNUM		int = 15
	PP_OFF_AUTHENTICATOR	int = 16
	PP_OFF_ATTRS		int = 32
)

const (
	//packet length definition
	MIN_PORTALPACKET_LEN	int = 32
	MAX_PORTALPACKET_LEN	int = 1024

	//portal version definition
	MIN_PORTALVERSION	int = 2

	//portal authenticator length
	PORTAL_AUTHENTICATOR_LEN	int = 16
	PORTAL_CHAP_LEN          int = 16
	PORTAL_CHAPPASSWD_LEN    int = 16
)

const (
	ATTRTYPE_USERNAME     = 1
	ATTRTYPE_PASSWD       = 2
	ATTRTYPE_CHALLENGE    = 3
	ATTRTYPE_CHAPPASSWD   = 4
	ATTRTYPE_TEXTINFO     = 5
	ATTRTYPE_UPLINKFLUX   = 6
	ATTRTYPE_DOWNLINKFLUX = 7
	ATTRTYPE_PORT         = 8
	ATTRTYPE_IPCONFIG     = 9
	ATTRTYPE_BASIP        = 10
	ATTRTYPE_SESSIONID    = 11
	ATTRTYPE_DELAYTIME    = 12
	ATTRTYPE_USERIPV6     = 241
)

type PortalPacket struct {
	Originator    *net.UDPAddr         // The origin IP address of the packet
	SharedSecret  string               // Shared Secret
	PortalVersion uint
	Version       uint8
	PortalType    uint8
	AuthMode      uint8
	Rsvd          uint8
	SerialNo      uint16
	ReqID         uint16
	UserIP        uint32
	UserPort      uint16
	ErrCode       uint8
	AttrNum       uint8
	PackageType   uint
	Authenticator []byte               // Authenticator Signature
	AVPS          []AttributeValuePair // A list of Attribute-value Pairs
	Raw           []byte               // A buffer with the original raw data
	UserIPStr     string
}

// Attribute-Value Pair structure
type AttributeValuePair struct {
	Name    string
	Type    uint8
	Length  uint8
	Content string
}

func (p *PortalPacket) Marshal() []byte {
	packetBuffer := make([]byte, 0, MAX_PORTALPACKET_LEN)
	packet := bytes.NewBuffer(packetBuffer)

	// Write Packet Code & ID
	packet.WriteByte(byte(p.Version))
	packet.WriteByte(byte(p.PortalType))
	packet.WriteByte(byte(p.AuthMode))
	packet.WriteByte(byte(p.Rsvd))
	binary.Write(packet, binary.BigEndian, p.SerialNo)
	binary.Write(packet, binary.BigEndian, p.ReqID)
	binary.Write(packet, binary.BigEndian, p.UserIP)
	binary.Write(packet, binary.BigEndian, p.UserPort)
	packet.WriteByte(byte(p.ErrCode))
	packet.WriteByte(byte(p.AttrNum))
	if p.PortalVersion == DEF_PORTAL_VERSION2 {
		if p.PackageType == PACKETTYPE_REQ {
			p.Authenticator = []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0} // 16 Zero Octets
		}
	}
	avpBuffer := make([]byte, 0, MAX_PORTALPACKET_LEN-32)
	avps := bytes.NewBuffer(avpBuffer)
	if len(p.AVPS) > 0 {
		for _, avp := range p.AVPS {
			avps.WriteByte(byte(avp.Type))
			avps.WriteByte(byte(avp.Length))
			avps.Write([]byte(avp.Content))
		}
	}
	if p.PortalVersion == DEF_PORTAL_VERSION2 {
		// Calculate Authenticator
		h := md5.New()
		temp := packet.Bytes()
		h.Write(temp[0:PP_OFF_AUTHENTICATOR])
		h.Write(p.Authenticator)
		if len(p.AVPS) > 0 {
			h.Write(avps.Bytes())
		}
		io.WriteString(h, p.SharedSecret)
		p.Authenticator = h.Sum(nil)
		packet.Write(p.Authenticator)
	}
	if len(p.AVPS) > 0 {
		packet.Write(avps.Bytes())
	}
	return packet.Bytes()
}

func (p *PortalPacket) UnMarshal() (err error) {
	if len(p.Raw) < PP_OFF_AUTHENTICATOR {
		// to less package.
		return
	}
	p.Version = uint8(p.Raw[PP_OFF_VERSION])
	p.PortalType = uint8(p.Raw[PP_OFF_TYPE])
	p.AuthMode = uint8(p.Raw[PP_OFF_AUTHMODE])
	p.Rsvd = uint8(p.Raw[PP_OFF_RSVD])
	p.SerialNo = uint16(p.Raw[PP_OFF_SERIALNO+1]) | uint16(p.Raw[PP_OFF_SERIALNO]) << 8
	p.ReqID = uint16(p.Raw[PP_OFF_REQID+1]) | uint16(p.Raw[PP_OFF_REQID]) << 8
	p.UserIP = uint32(p.Raw[PP_OFF_USERIP+3]) | uint32(p.Raw[PP_OFF_USERIP+2])<<8 | uint32(p.Raw[PP_OFF_USERIP+1])<<16 | uint32(p.Raw[PP_OFF_USERIP])<<24
	p.UserIPStr = p.ParseIP(p.Raw[PP_OFF_USERIP:PP_OFF_USERIP+4])
	p.UserPort = uint16(p.Raw[PP_OFF_USERPORT+1]) | uint16(p.Raw[PP_OFF_USERPORT]) << 8
	p.ErrCode = uint8(p.Raw[PP_OFF_ERRCODE])
	p.AttrNum = uint8(p.Raw[PP_OFF_ATTRNUM])
	var index int = PP_OFF_ATTRS
	if p.PortalVersion == DEF_PORTAL_VERSION2 {
		p.Authenticator = p.Raw[PP_OFF_AUTHENTICATOR:PP_OFF_AUTHENTICATOR+PP_AUTHENTICATOR_LEN]
	} else {
		index = PP_OFF_AUTHENTICATOR
	}
	var ii uint8

	for ii = 0; ii < p.AttrNum; ii++ {
		var attr AttributeValuePair
		attr.Type = uint8(p.Raw[index])
		index++
		attr.Length = uint8(p.Raw[index])
		index++
		attr.Content = string(p.Raw[index:index+int(attr.Length)])
		index += int(attr.Length)
	}
	return
}

// Verifies the Authenticator Field if it matches our shared-secret
func (p *PortalPacket) VerifyAuthenticator() bool {
	// Calculate Authenticator Hash
	h := md5.New()
	h.Write(p.Raw[0:PP_OFF_AUTHENTICATOR])                          // Header
	if p.PackageType == PACKETTYPE_REQ {
		h.Write([]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}) // 16 Zero Octets
	} else if len(p.Authenticator) == PP_AUTHENTICATOR_LEN {
		h.Write(p.Authenticator)
	} else {
		return false
	}
	h.Write(p.Raw[PP_OFF_ATTRS:])                                   // Attributes
	h.Write([]byte(p.SharedSecret))                                 // Shared-Secret, as retrieved by SharedSecret Callback
	ours := h.Sum(nil)

	// Loop & compare byte-by-byte
	for i := 0; i < 16; i++ {
		if p.Raw[4+i] != ours[i] {
			return false
		}
	}

	return true
}

// Parses IP Addresses
func (p *PortalPacket)ParseIP(content []byte) string {
	return fmt.Sprintf("%d.%d.%d.%d", content[0], content[1], content[2], content[3])
}

func (p *PortalPacket) PortalTypeString() (desc string) {
	switch p.PortalType {
	case PACKETTYPE_REQCHALLENGE:
		desc = "REQ_CHALLENGE"
	case PACKETTYPE_ACKCHALLENGE:
		desc = "ACK_CHALLENGE"
	case PACKETTYPE_REQAUTH:
		desc = "REQ_AUTH"
	case PACKETTYPE_ACKAUTH:
		desc = "ACK_AUTH"
	case PACKETTYPE_REQLOGOUT:
		desc = "REQ_LOGOUT"
	case PACKETTYPE_ACKLOGOUT:
		desc = "ACK_LOGOUT"
	case PACKETTYPE_AFFACKAUTH:
		desc = "AFF_ACK_AUTH"
	case PACKETTYPE_NTFLOGOUT:
		desc = "NTF_LOGOUT"
	case PACKETTYPE_REQINFO:
		desc = "REQ_INFO"
	case PACKETTYPE_ACKINFO:
		desc = "ACK_INFO"
	default:
	}
	return
}

func (p *PortalPacket) PacketTypeString() (desc string) {
	switch p.PackageType {
	case PACKETTYPE_REQ:
		desc = "REQ";
		break;
	case PACKETTYPE_RSP:
		desc = "RSP";
		break;
	default:
	}
	return
}

func (p *AttributeValuePair) AttrTypeString() string {
	switch p.Type {
	case ATTRTYPE_USERNAME:
		p.Name = "USERNAME"
	case ATTRTYPE_PASSWD:
		p.Name = "PASSWD"
	case ATTRTYPE_CHALLENGE:
		p.Name = "CHALLENGE"
	case ATTRTYPE_CHAPPASSWD:
		p.Name = "CHAPPASSWD"
	case ATTRTYPE_TEXTINFO:
		p.Name = "TEXTINFO"
	case ATTRTYPE_UPLINKFLUX:
		p.Name = "UPLINKFLUX"
	case ATTRTYPE_DOWNLINKFLUX:
		p.Name = "DOWNLINKFLUX"
	case ATTRTYPE_PORT:
		p.Name = "PORT"
	case ATTRTYPE_IPCONFIG:
		p.Name = "IPCONFIG"
	case ATTRTYPE_BASIP:
		p.Name = "BASIP"
	case ATTRTYPE_SESSIONID:
		p.Name = "SESSIONID"
	case ATTRTYPE_DELAYTIME:
		p.Name = "DELAYTIME"
	case ATTRTYPE_USERIPV6:
		p.Name = "USERIPV6"
	default:
		p.Name = "UNKNOWN"
	}
	return p.Name
}