package logic

import (
	"bytes"
	"encoding/binary"
	"crypto/md5"
	logger "github.com/shengkehua/xlog4go"
	"config"
)

//const variables definition
const (
	PCMERR_OK = 0
	PCMERR_UNKNOWN = 1
	PCMERR_CHALLENGEREFUSED = 2
	PCMERR_CONNECTCREATED = 3
	PCMERR_SAMEUSERAUTHING = 4
	PCMERR_AUTHREFUSED = 5
	PCMERR_RECVTIMEOUT = 6
	PCMERR_LOGOUTREFUSED = 7
)

//status code
const (
	PCMSTATUS_START = 1
	PCMSTATUS_CHALLENGE = 2           //CHALLENGE stage
	PCMSTATUS_AUTH = 3                //AUTH stage
	PCMSTATUS_LOGOUT = 4              //LOGOUT stage
	PCMSTATUS_VLANINFO = 5
	PCMSTATUS_NTFLOGOUT = 6
)

//request type
const (
	PCMREQTYPE_CHALLENGE = 1
	PCMREQTYPE_AUTH = 2
	PCMREQTYPE_AFFACKAUTH = 3
	PCMREQTYPE_LOGOUT = 4
	PCMREQTYPE_NTFLOGOUT = 5
	PCMREQTYPE_ACKLOGOUT = 6
	PCMREQTYPE_INFO = 7
)

type PortalClient struct {
	UserName         string
	Password         string
	BrasIP           string
	FrameIP          string
	UserMac          string
	ChapPassword     string
	SerialNo         uint16
	ErrCode          uint8
	ReqId            uint16
	Status           uint8
	Packet           *PortalPacket
	PortInfo         string
	TextInfo         string
	AuthType         string
	IsSendAffAckAuth bool
}

//Get current serial no and increment it
func (p *PortalClient) NewSerialNo() uint16 {
	if p.SerialNo == 0xFFFF {
		p.SerialNo = 0
	}
	p.SerialNo++
	return p.SerialNo
}

//do REQ_CHALLENGE
func (p *PortalClient) ReqChallenge() (ret bool) {
	//set the default error code
	p.ErrCode = PCMERR_UNKNOWN;

	//make REQ_CHALLENGE packet
	if !p.MakeRequestPacket(PCMREQTYPE_CHALLENGE) {
		logger.Error("make CHALLENGE request packet failed.")
		return
	}

	logger.Debug("make CHALLENGE request packet ok.")

	//send REQ_CHALLENGE packet and receive ack
	if !p.SendReqAndRecvAckPkt(PCMREQTYPE_CHALLENGE) {
		logger.Error("receive chanllege ack failed.")
		p.ErrCode = PCMERR_RECVTIMEOUT
		return
	}

	var portalPacket = &PortalPacket{}

	logger.Debug("send CHALLENGE request packet ok.")
	//Analyze the ACK_CHALLENGE packet
	portalPacket.PackageType = PACKETTYPE_RSP
	portalPacket.PortalVersion = DEF_PORTAL_VERSION2
	portalPacket.SharedSecret = config.Cfg.SharedSecret
	portalPacket.Authenticator = p.Packet.Authenticator
	portalPacket.Raw = p.Packet.Raw
	//analyze the ack packet
	portalPacket.UnMarshal()

	logger.Debug("parse CHALLENGE ack packet ok.")

	//dump ack packet to buffer
	portalPacket.HexDumpString()

	//check the serial no and packet type
	if p.Packet.SerialNo != portalPacket.SerialNo || portalPacket.PackageType != PACKETTYPE_ACKCHALLENGE {
		//serial no not matched.
		logger.Error("serial not matched for CHALLENGE ack. [%v/%v]", p.Packet.SerialNo, portalPacket.SerialNo);
		return
	}

	//check error code
	switch portalPacket.ErrCode {
	case 0:
		//ok
		p.ErrCode = PCMERR_OK;
	case 1:
		//REQ_CHALLENGE refused
		p.ErrCode = PCMERR_CHALLENGEREFUSED
	case 2:
		//connection created
		p.ErrCode = PCMERR_CONNECTCREATED
	case 3:
		//same user authenticating
		p.ErrCode = PCMERR_SAMEUSERAUTHING
	default:
		p.ErrCode = PCMERR_UNKNOWN
	}

	var exist bool
	var attr AttributeValuePair
	//get the TEXTINFO attrib if have
	exist, attr = p.Packet.GetAttrByType(ATTRTYPE_TEXTINFO)
	if !exist {
		logger.Error("get textinfo is NULL!");
	} else {
		p.TextInfo = attr.Content
	}

	//if ack failed, return
	if p.ErrCode != PCMERR_OK {
		logger.Error("CHALLENGE return error. [%v]", p.ErrCode)
		return
	}

	//save the req id
	p.ReqId = portalPacket.ReqID

	//Get the chap challenge attrib
	exist, attr = p.Packet.GetAttrByType(ATTRTYPE_CHALLENGE)
	if !exist {
		logger.Error("get CHAP challenge is failed!")
		return
	} else {
		p.ChapPassword = attr.Content
	}

	logger.Debug("get CHALLENGE attrib from ack packet ok.")

	//calculate CHAP_CHALLENGE attrib
	p.ChapPassword = p.CalcChapPassword(p.ReqId, p.Password, p.ChapPassword)

	logger.Debug("do CHALLENGE request ok.")
	return
}

//do REQ_AUTH
func (p *PortalClient) ReqAuth() (ret bool) {
	//set default error code
	p.ErrCode = PCMERR_UNKNOWN;

	//make REQ_AUTH packet
	if !p.MakeRequestPacket(PCMREQTYPE_AUTH) {
		logger.Error("make AUTHEN packet failed during login.")
		return
	}
	logger.Debug("make AUTHEN packet ok during login.")

	//send REQ_CHALLENGE packet and receive ack
	if !p.SendReqAndRecvAckPkt(PCMREQTYPE_AUTH) {
		logger.Error("send AUTHEN request or recv AUTHEN ack failed.")
		p.ErrCode = PCMERR_RECVTIMEOUT
		return
	}

	logger.Debug("send AUTHEN request or recv AUTHEN ack ok.");
	p.Packet = &PortalPacket{}
	//Analyze the ACK_CHALLENGE packet
	//request authenticator saved in the m_pppAuthenticator
	p.Packet.PackageType = PACKETTYPE_RSP
	p.Packet.PortalVersion = DEF_PORTAL_VERSION2
	p.Packet.SharedSecret = config.Cfg.SharedSecret


	//analyze the ack packet
	if err := p.Packet.UnMarshal(); err != nil {
		logger.Error("parse AUTHEN ack packet failed.")
		return
	}
	//dump ack packet to buffer
	p.Packet.HexDumpString()

	logger.Debug("parse AUTHEN ack packet ok.")

	//set error code
	switch p.Packet.ErrCode {
	case 0:
		//authen ok
		p.ErrCode = PCMERR_OK
	case 1:
		//authen refused
		p.ErrCode = PCMERR_AUTHREFUSED;
	case 2:
		//connection created
		p.ErrCode = PCMERR_CONNECTCREATED;
	case 3:
		//same user authenticating
		p.ErrCode = PCMERR_SAMEUSERAUTHING;
	default:
		p.ErrCode = PCMERR_UNKNOWN;
		break;
	}
	var exist bool
	var attr AttributeValuePair
	//save the port info
	exist, attr = p.Packet.GetAttrByType(ATTRTYPE_TEXTINFO)
	if !exist {
		logger.Error("get textinfo is NULL!");
	} else {
		p.TextInfo = attr.Content
	}

	//check the error code
	if p.ErrCode != PCMERR_OK {
		logger.Error("REQ_AUTH error. [%v]", p.ErrCode)
		return
	} else {
		//check the serial no and packet type
		if p.SerialNo != p.Packet.SerialNo || p.Packet.PackageType != PACKETTYPE_ACKAUTH {
			logger.Error("serial no not matched or packet type invalid.")
			p.ErrCode = PCMERR_UNKNOWN
			return
		}
	}

	logger.Debug("parse AUTHEN ack packet ok.")

	//send the AFF_ACK_AUTH according to the
	if (p.IsSendAffAckAuth) {
		//make AFF_ACK_AUTH packet

		//save the req id for PAP
		p.ReqId = p.Packet.ReqID
		if p.MakeRequestPacket(PCMREQTYPE_AFFACKAUTH) {
			logger.Error("make AFF AUTHEN ack request packet failed.")
			p.ErrCode = PCMERR_UNKNOWN;
			return
		}

		//send the AFF_ACK_AUTH packet
		if !p.SendReqAndRecvAckPkt(PCMREQTYPE_AFFACKAUTH) {
			logger.Error("send AFF AUTHEN request or receive AFF AUTHEN ack failed.")
			p.ErrCode = PCMERR_UNKNOWN
			return
		}
		logger.Debug("send AFF AUTHEN request and receive AFF AUTHEN ack ok.")
	}
	logger.Debug("do AUTHEN step ok during login")
	return
}

//do REQ_LOGOUT
func (p *PortalClient) ReqLogin() (ret bool) {
	p.Status = PCMSTATUS_AUTH
	if p.AuthType == "CHAP" {
		//need do CHALLENGE
		p.Status = PCMSTATUS_CHALLENGE
		if !p.ReqChallenge() {
			logger.Error("do CHALLENGE failed during login step.")
			return
		}
	}
	logger.Info("do CHALLENGE ok during login step.")
	p.Status = PCMSTATUS_AUTH
	if !p.ReqAuth() {
		logger.Error("do AUTHEN failed during login step.")
		return
	}
	logger.Info("do AUTHEN ok during login step.")
	return
}

//do REQ_LOGOUT
func (p *PortalClient) ReqLogout() (ret bool) {
	p.Status = PCMSTATUS_LOGOUT

	//set default error code
	p.ErrCode = PCMERR_UNKNOWN;

	//make REQ_LOGOUT packet
	if !p.MakeRequestPacket(PCMREQTYPE_LOGOUT) {
		logger.Error("make LOGOUT packet failed.")
		return
	}

	logger.Debug("make LOGOUT request packet ok.");

	//send and recv ack
	if !p.SendReqAndRecvAckPkt(PCMREQTYPE_LOGOUT) {
		logger.Error("send LOGOUT request packet failed.")
		return
	}

	logger.Debug("send LOGOUT request packet and receive response packet ok.")

	//if REQ_LOGOUT for REQ_CHALLENGE or REQ_AUTH, return directly
	if p.Status == PCMSTATUS_CHALLENGE || p.Status == PCMSTATUS_AUTH {
		logger.Warn("logout do nothing for CHALLENGE or AUTHEN.  [%v]", p.Status)
		return
	}
	var portalPacket = PortalPacket{}
	portalPacket.PackageType = PACKETTYPE_RSP
	portalPacket.PortalVersion = DEF_PORTAL_VERSION2
	portalPacket.SharedSecret = config.Cfg.SharedSecret
	portalPacket.Authenticator = p.Packet.Authenticator
	portalPacket.Raw = p.Packet.Raw
	if err := portalPacket.UnMarshal(); err != nil {
		logger.Error("parse LOGOUT ack packet failed.");
		return
	}

	logger.Debug("parse LOGOUT ack packet ok.")

	//dump ack packet to buffer
	portalPacket.HexDumpString()

	//check the serial no and packet type
	if p.SerialNo != portalPacket.SerialNo || portalPacket.PackageType == PACKETTYPE_ACKLOGOUT {
		logger.Error("serial no or portal type not matched.")
		return
	}

	//check error code
	switch portalPacket.ErrCode {
	case 0:
		//logout ok
		p.ErrCode = PCMERR_OK
	case 1:
		//logout refused
		p.ErrCode = PCMERR_LOGOUTREFUSED
	default:
		p.ErrCode = PCMERR_UNKNOWN
	}
	var attr AttributeValuePair
	var exist bool
	//get the TEXTINFO attrib if have
	exist, attr = p.Packet.GetAttrByType(ATTRTYPE_TEXTINFO)
	if !exist {
		logger.Error("get textinfo is NULL!");
	} else {
		p.TextInfo = attr.Content
	}

	//if ack failed, return
	if p.ErrCode != PCMERR_OK {
		logger.Error("do LOGOUT failed. [%v]", p.ErrCode);
		return
	}

	logger.Debug("do LOGOUT ok.")
	return
}

func (p *PortalClient) ReqVlaninfo() (ret bool) {
	p.Status = PCMSTATUS_VLANINFO
	//set default error code
	p.ErrCode = PCMERR_UNKNOWN

	//make REQ_GETVLANINFO packet
	if !p.MakeRequestPacket(PCMREQTYPE_INFO) {
		logger.Error("make getvlaninfo packet failed.")
		return
	}

	logger.Debug("make getvlaninfo request packet ok.")

	//send and recv ack
	if !p.SendReqAndRecvAckPkt(PCMREQTYPE_INFO) {
		logger.Error("send getvlaninfo request packet failed.")
		return
	}

	logger.Debug("send getvlaninfo request packet and receive response packet ok.");

	//if REQ_LOGOUT for REQ_CHALLENGE or REQ_AUTH, return directly
	if p.Status == PCMSTATUS_CHALLENGE || p.Status == PCMSTATUS_AUTH {
		logger.Warn("getvlaninfo do nothing for CHALLENGE or AUTHEN.  [%V]", p.Status)
		return
	}

	portalPacket := &PortalPacket{}
	portalPacket.PackageType = PACKETTYPE_RSP
	portalPacket.Authenticator = p.Packet.Authenticator
	portalPacket.PortalVersion = DEF_PORTAL_VERSION2
	portalPacket.SharedSecret = config.Cfg.SharedSecret
	//analyze the ack packet
	if err := portalPacket.UnMarshal(); err != nil {
		logger.Error("parse VLANINFO ack packet failed.")
		return
	}

	logger.Debug("parse VLANINFO ack packet ok.")
	//dump ack packet to buffer
	portalPacket.HexDumpString()

	//check the serial no and packet type
	if p.SerialNo != portalPacket.SerialNo || portalPacket.PackageType != PACKETTYPE_ACKINFO {
		logger.Error("serial no or portal type not matched.")
		return
	}

	var exist bool
	var attr AttributeValuePair
	//save the port info
	exist, attr = portalPacket.GetAttrByType(ATTRTYPE_PORT)
	if !exist {
		logger.Error("get tlvAttrib forportinfo is NULL!");
	} else {
		p.PortInfo = attr.Content
	}
	p.ErrCode = portalPacket.ErrCode
	//if ack failed, return
	if p.ErrCode != PCMERR_OK {
		logger.Error("do GETVLANINFO failed. [%lu]", p.ErrCode);
		return
	}

	logger.Debug("do GETVLANINFO ok.")
	return
}

//make request packet according current status
//used by portal server
func (p *PortalClient) MakeRequestPacket(reqType int) (ret bool) {
	//check the request type
	if reqType < PCMREQTYPE_CHALLENGE || reqType > PCMREQTYPE_INFO {
		logger.Error("req type invalid. ")
		return
	}
	p.Packet = &PortalPacket{}


	//get the serial no of request
	//if AFF_ACK_AUTH, we use current error code
	//if REQ_LOGOUT, we need check the current error code
	if reqType == PCMREQTYPE_AFFACKAUTH ||
	(reqType == PCMREQTYPE_LOGOUT) && (p.Status == PCMSTATUS_CHALLENGE || p.Status == PCMSTATUS_AUTH) {
		//if REQ_CHALLENGE or REQ_AUTH failed, we use the current serial no
		//it's not necessary to get a new serial no
		logger.Warn("REQ_LOGOUT for REQ_AUTH or REQ_CHALLENGE. [%v]", p.ErrCode);
	} else {
		//get a new serial no
		//get vlaninfo use new  serial no
		p.SerialNo = p.NewSerialNo()
		logger.Info("new serial no: %v", p.SerialNo);
	}

	if p.AuthType == "CHAP" {
		//reqid is valid for CHAP
		if reqType == PCMREQTYPE_AUTH || reqType == PCMREQTYPE_AFFACKAUTH || reqType == PCMREQTYPE_LOGOUT {
			//if REQ_AUTH, AFF_ACK_AUTH or REQ_LOGOUT
			//m_pcmCurReqID got in ACK_CHALLENGE
			//get the request id
			p.Packet.ReqID = p.ReqId
		}
	} else if p.AuthType == "PAP" {
		// aff_ack_auth req_id is equal to ack_auth
		if reqType == PCMREQTYPE_AFFACKAUTH {
			p.Packet.ReqID = p.ReqId
			logger.Info("AFF_ACK_AUTH PAP request id: %v", p.Packet.ReqID);
		}
	}

	if reqType == PCMREQTYPE_LOGOUT {
		//check current error code
		if p.Status == PCMSTATUS_CHALLENGE || p.Status == PCMSTATUS_AUTH {
			//REQ_LOGOUT from REQ_CHALLENGE or REQ_AUTH
			//we need set it to 1
			p.Packet.ErrCode = 1;
		}
	}

	//append all the attribs
	if reqType == PCMREQTYPE_AUTH {
		//attrib number is 2: user name and user passwd
		p.Packet.AttrNum = 2
		//append the username
		var attr AttributeValuePair
		attr.Type = ATTRTYPE_USERNAME
		attr.Content = p.UserName
		attr.Length = uint8(len(attr.Content))
		p.Packet.AVPS = append(p.Packet.AVPS, attr)

		//append the passwd or chap-passwd attrib
		if p.AuthType == "CHAP" {
			//append the user passwd
			attr.Type = ATTRTYPE_CHAPPASSWD
			attr.Content = p.ChapPassword
			attr.Length = uint8(len(attr.Content))
			p.Packet.AVPS = append(p.Packet.AVPS, attr)
			p.Packet.AuthMode = AUTHMODE_CHAP;
		} else {
			//append the user passwd
			attr.Type = ATTRTYPE_PASSWD
			attr.Content = p.Password
			attr.Length = uint8(len(attr.Content))
			p.Packet.AVPS = append(p.Packet.AVPS, attr)
			p.Packet.AuthMode = AUTHMODE_PAP;
		}
	}
	if reqType == PCMREQTYPE_INFO {
		p.Packet.AttrNum = 1
		//append port type and len
		var attr AttributeValuePair
		attr.Type = ATTRTYPE_PORT
		attr.Content = ""
		attr.Length = 0
		p.Packet.AVPS = append(p.Packet.AVPS, attr)
	}
	//convert to packet buffer
	p.Packet.Marshal()
	return
}

//get request type according current status
func (p *PortalClient) GetReqTypeByStatus() (desc string) {
	switch p.Status {
	case PCMSTATUS_CHALLENGE:
		desc = "REQ_CHALLENGE"
	case PCMSTATUS_AUTH:
		desc = "REQ_AUTH"
	case PCMSTATUS_LOGOUT:
		desc = "REQ_LOGOUT"
	default:
		break
	}
	return
}

//send the request packet and receive ack packet
//this function must be called after MakeRequestPacket
//received ack packet stored in m_pcmAckPktBuf.
func (p *PortalClient) SendReqAndRecvAckPkt(packetType int) (ret bool) {
	//check the request type
	if (packetType < PCMREQTYPE_CHALLENGE) || (packetType > PCMREQTYPE_INFO) {
		logger.Error("request type invalid. ")
		return
	}
	var bRecvAck bool = true;
	if (packetType == PCMREQTYPE_AFFACKAUTH) ||
	(packetType == PCMREQTYPE_ACKLOGOUT) ||
	((packetType == PCMREQTYPE_LOGOUT) &&
	((p.Status == PCMSTATUS_CHALLENGE) ||
	(p.Status == PCMSTATUS_AUTH))) {
		//It's not necessary to receive ack
		bRecvAck = false;
	}
	for ii := 0; ii < config.Cfg.RetryTime; ii++ {
		//send and recv
		//check whether we need receive ack packet
		if !bRecvAck {
			logger.Debug("need not receive ack packet.")
			ret = true
			break
		}
		// recv len
		//GetMinPktLen
		var rbytes int
		if rbytes < p.Packet.GetMinPktLen() {
			logger.Error("receive ack packet too short. [%v]", rbytes)
			continue;
		}
		//recv
		ret = true
		break
	}
	return
}

func (p *PortalClient) CalcChapPassword(reqId uint16, password, chapChallenge string) (chapPasswd string) {
	packetBuffer := make([]byte, 0, 2)
	packet := bytes.NewBuffer(packetBuffer)
	binary.Write(packet, binary.BigEndian, reqId)
	// Calculate Authenticator Hash
	h := md5.New()
	h.Write(packet.Bytes()[1:1])
	h.Write([]byte(password))
	h.Write([]byte(chapChallenge))
	ours := h.Sum(nil)
	chapPasswd = string(ours)
	return
}