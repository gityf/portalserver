package logic

import (
	"bytes"
	"encoding/binary"
	"crypto/md5"
	logger "github.com/xlog4go"
	"config"
	"net"
	"util"
	"global"
	"time"
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

type PortalClient struct {
	UserName         string
	Password         string
	BrasIP           string
	UserIP           string
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
	p.ErrCode = PCMERR_UNKNOWN

	//make REQ_CHALLENGE packet
	if !p.MakeRequestPacket(PACKETTYPE_REQCHALLENGE) {
		logger.Error("make CHALLENGE request packet failed.")
		return
	}

	logger.Debug("make CHALLENGE request packet ok.")
	logger.Debug("CHALLENGE serial:%v,requ:\n%v", p.SerialNo, p.Packet.HexDumpString())

	//send REQ_CHALLENGE packet and receive ack
	if !p.SendReqAndRecvAckPkt(PACKETTYPE_REQCHALLENGE) {
		logger.Error("receive chanllege ack failed.")
		p.ErrCode = PCMERR_RECVTIMEOUT
		return
	}
	logger.Debug("send CHALLENGE request packet ok.")
	//Analyze the ACK_CHALLENGE packet
	p.Packet.PackageType = PACKETTYPE_RSP
	p.Packet.PortalVersion = DEF_PORTAL_VERSION2
	//analyze the ack packet
	p.Packet.UnMarshal()

	logger.Debug("parse CHALLENGE ack packet ok.")

	//dump ack packet to buffer
	logger.Debug("CHALLENGE serial:%v,resp:\n%v", p.SerialNo, p.Packet.HexDumpString())
	if !p.Packet.VerifyAuthenticator() {
		//serial no not matched.
		logger.Error("VerifyAuthenticator err serial:%v", p.Packet.SerialNo)
		return
	}

	//check the serial no and packet type
	if p.SerialNo != p.Packet.SerialNo || p.Packet.PortalType != PACKETTYPE_ACKCHALLENGE {
		//serial no not matched.
		logger.Error("serial not matched for CHALLENGE ack. [%v/%v]", p.SerialNo, p.Packet.SerialNo)
		return
	}

	//check error code
	switch p.Packet.ErrCode {
	case 0:
		//ok
		p.ErrCode = PCMERR_OK
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
		logger.Error("get textinfo is NULL!")
	} else {
		p.TextInfo = attr.Content
	}

	//if ack failed, return
	if p.ErrCode != PCMERR_OK {
		logger.Error("CHALLENGE return error. [%v]", p.ErrCode)
		return
	}

	//save the req id
	p.ReqId = p.Packet.ReqID

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
	p.ErrCode = PCMERR_UNKNOWN

	//make REQ_AUTH packet
	if !p.MakeRequestPacket(PACKETTYPE_REQAUTH) {
		logger.Error("make AUTHEN packet failed during login.")
		return
	}
	logger.Debug("make AUTHEN packet ok during login.")
	logger.Debug("AUTHEN serial:%v,requ:\n%v", p.SerialNo, p.Packet.HexDumpString())

	//send REQ_CHALLENGE packet and receive ack
	if !p.SendReqAndRecvAckPkt(PACKETTYPE_REQAUTH) {
		logger.Error("send AUTHEN request or recv AUTHEN ack failed.")
		p.ErrCode = PCMERR_RECVTIMEOUT
		return
	}

	logger.Debug("send AUTHEN request or recv AUTHEN ack ok.")
	//Analyze the ACK_CHALLENGE packet
	//request authenticator saved in the m_pppAuthenticator
	p.Packet.PackageType = PACKETTYPE_RSP
	p.Packet.PortalVersion = DEF_PORTAL_VERSION2


	//analyze the ack packet
	if err := p.Packet.UnMarshal(); err != nil {
		logger.Error("parse AUTHEN ack packet failed.")
		return
	}
	//dump ack packet to buffer
	logger.Debug("Auth serial:%v,resp:\n%v", p.SerialNo, p.Packet.HexDumpString())

	if !p.Packet.VerifyAuthenticator() {
		//serial no not matched.
		logger.Error("VerifyAuthenticator err serial:%v", p.Packet.SerialNo)
		return
	}
	logger.Debug("parse AUTHEN ack packet ok.")

	//set error code
	switch p.Packet.ErrCode {
	case 0:
		//authen ok
		p.ErrCode = PCMERR_OK
	case 1:
		//authen refused
		p.ErrCode = PCMERR_AUTHREFUSED
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
	//save the port info
	exist, attr = p.Packet.GetAttrByType(ATTRTYPE_TEXTINFO)
	if !exist {
		logger.Error("get textinfo is NULL!")
	} else {
		p.TextInfo = attr.Content
	}

	//check the error code
	if p.ErrCode != PCMERR_OK {
		logger.Error("REQ_AUTH error. [%v]", p.ErrCode)
		return
	} else {
		//check the serial no and packet type
		if p.SerialNo != p.Packet.SerialNo || p.Packet.PortalType != PACKETTYPE_ACKAUTH {
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
		if p.MakeRequestPacket(PACKETTYPE_AFFACKAUTH) {
			logger.Error("make AFF AUTHEN ack request packet failed.")
			p.ErrCode = PCMERR_UNKNOWN
			return
		}

		//send the AFF_ACK_AUTH packet
		if !p.SendReqAndRecvAckPkt(PACKETTYPE_AFFACKAUTH) {
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
	p.ErrCode = PCMERR_UNKNOWN

	//make REQ_LOGOUT packet
	if !p.MakeRequestPacket(PACKETTYPE_REQLOGOUT) {
		logger.Error("make LOGOUT packet failed.")
		return
	}

	logger.Debug("make LOGOUT request packet ok.")
	logger.Debug("LOGOUT serial:%v,requ:\n%v", p.SerialNo, p.Packet.HexDumpString())

	//send and recv ack
	if !p.SendReqAndRecvAckPkt(PACKETTYPE_REQLOGOUT) {
		logger.Error("send LOGOUT request packet failed.")
		return
	}

	logger.Debug("send LOGOUT request packet and receive response packet ok.")

	//if REQ_LOGOUT for REQ_CHALLENGE or REQ_AUTH, return directly
	if p.Status == PCMSTATUS_CHALLENGE || p.Status == PCMSTATUS_AUTH {
		logger.Warn("logout do nothing for CHALLENGE or AUTHEN.  [%v]", p.Status)
		return
	}
	p.Packet.PackageType = PACKETTYPE_RSP
	p.Packet.PortalVersion = DEF_PORTAL_VERSION2
	if err := p.Packet.UnMarshal(); err != nil {
		logger.Error("parse LOGOUT ack packet failed.")
		return
	}

	logger.Debug("parse LOGOUT ack packet ok.")

	//dump ack packet to buffer
	logger.Debug("Logout serial:%v, resp:\n%v", p.SerialNo, p.Packet.HexDumpString())

	//check the serial no and packet type
	if p.SerialNo != p.Packet.SerialNo || p.Packet.PortalType == PACKETTYPE_ACKLOGOUT {
		logger.Error("serial no or portal type not matched.")
		return
	}

	//check error code
	switch p.Packet.ErrCode {
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
		logger.Error("get textinfo is NULL!")
	} else {
		p.TextInfo = attr.Content
	}

	//if ack failed, return
	if p.ErrCode != PCMERR_OK {
		logger.Error("do LOGOUT failed. [%v]", p.ErrCode)
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
	if !p.MakeRequestPacket(PACKETTYPE_REQINFO) {
		logger.Error("make getvlaninfo packet failed.")
		return
	}

	logger.Debug("make getvlaninfo request packet ok.")
	logger.Debug("VLANINFO serial:%v,requ:\n%v", p.SerialNo, p.Packet.HexDumpString())

	//send and recv ack
	if !p.SendReqAndRecvAckPkt(PACKETTYPE_REQINFO) {
		logger.Error("send getvlaninfo request packet failed.")
		return
	}

	logger.Debug("send getvlaninfo request packet and receive response packet ok.")

	//if REQ_LOGOUT for REQ_CHALLENGE or REQ_AUTH, return directly
	if p.Status == PCMSTATUS_CHALLENGE || p.Status == PCMSTATUS_AUTH {
		logger.Warn("getvlaninfo do nothing for CHALLENGE or AUTHEN.  [%V]", p.Status)
		return
	}

	p.Packet.PackageType = PACKETTYPE_RSP
	p.Packet.PortalVersion = DEF_PORTAL_VERSION2
	//analyze the ack packet
	if err := p.Packet.UnMarshal(); err != nil {
		logger.Error("parse VLANINFO ack packet failed.")
		return
	}

	logger.Debug("parse VLANINFO ack packet ok.")
	//dump ack packet to buffer
	logger.Debug("VLANINFO serial:%v, resp:\n%v", p.SerialNo, p.Packet.HexDumpString())

	//check the serial no and packet type
	if p.SerialNo != p.Packet.SerialNo || p.Packet.PortalType != PACKETTYPE_ACKINFO {
		logger.Error("serial no or portal type not matched.")
		return
	}

	var exist bool
	var attr AttributeValuePair
	//save the port info
	exist, attr = p.Packet.GetAttrByType(ATTRTYPE_PORT)
	if !exist {
		logger.Error("get tlvAttrib forportinfo is NULL!")
	} else {
		p.PortInfo = attr.Content
	}
	p.ErrCode = p.Packet.ErrCode
	//if ack failed, return
	if p.ErrCode != PCMERR_OK {
		logger.Error("do GETVLANINFO failed. [%lu]", p.ErrCode)
		return
	}

	logger.Debug("do GETVLANINFO ok.")
	return
}

//make request packet according current status
//used by portal server
func (p *PortalClient) MakeRequestPacket(reqType uint8) (ret bool) {
	//check the request type
	if reqType < PACKETTYPE_REQCHALLENGE || reqType > PACKETTYPE_REQINFO {
		logger.Error("req type invalid. ")
		return
	}
	p.Packet = &PortalPacket{}
	p.Packet.SharedSecret = config.Cfg.SharedSecret
	p.Packet.Version = DEF_PORTAL_VERSION2
	p.Packet.PortalType = reqType
	p.Packet.PortalVersion = DEF_PORTAL_VERSION2
	p.Packet.UserIP = inet_aton(p.UserIP)
	p.Packet.UserPort = 0
	p.Packet.PackageType = PACKETTYPE_REQ

	//get the serial no of request
	//if AFF_ACK_AUTH, we use current error code
	//if REQ_LOGOUT, we need check the current error code
	if reqType == PACKETTYPE_AFFACKAUTH ||
	(reqType == PACKETTYPE_REQLOGOUT) && (p.Status == PCMSTATUS_CHALLENGE || p.Status == PCMSTATUS_AUTH) {
		//if REQ_CHALLENGE or REQ_AUTH failed, we use the current serial no
		//it's not necessary to get a new serial no
		logger.Warn("REQ_LOGOUT for REQ_AUTH or REQ_CHALLENGE. [%v]", p.ErrCode)
	} else {
		//get a new serial no
		//get vlaninfo use new  serial no
		p.SerialNo = p.NewSerialNo()
		logger.Info("new serial no: %v", p.SerialNo)
	}
	p.Packet.SerialNo = p.SerialNo

	if p.AuthType == "CHAP" {
		//reqid is valid for CHAP
		if reqType == PACKETTYPE_REQAUTH || reqType == PACKETTYPE_AFFACKAUTH || reqType == PACKETTYPE_REQLOGOUT {
			//if REQ_AUTH, AFF_ACK_AUTH or REQ_LOGOUT
			//m_pcmCurReqID got in ACK_CHALLENGE
			//get the request id
			p.Packet.ReqID = p.ReqId
		}
		p.Packet.AuthMode = AUTHMODE_CHAP
	} else if p.AuthType == "PAP" {
		// aff_ack_auth req_id is equal to ack_auth
		if reqType == PACKETTYPE_AFFACKAUTH {
			p.Packet.ReqID = p.ReqId
			logger.Info("AFF_ACK_AUTH PAP request id: %v", p.Packet.ReqID)
		}
		p.Packet.AuthMode = AUTHMODE_PAP
	}

	if reqType == PACKETTYPE_REQLOGOUT {
		//check current error code
		if p.Status == PCMSTATUS_CHALLENGE || p.Status == PCMSTATUS_AUTH {
			//REQ_LOGOUT from REQ_CHALLENGE or REQ_AUTH
			//we need set it to 1
			p.Packet.ErrCode = 1
		}
	}

	//append all the attribs
	if reqType == PACKETTYPE_REQAUTH {
		//attrib number is 2: user name and user passwd
		p.Packet.AttrNum = 2
		//append the username
		var attr AttributeValuePair
		attr.Type = ATTRTYPE_USERNAME
		attr.Content = p.UserName
		attr.Length = uint8(len(attr.Content))
		p.Packet.AVPS = append(p.Packet.AVPS, attr)
		logger.Debug("username:%v,type:%v,len:%v,srclen:%v",
			attr.Content, attr.Type, attr.Length, len(attr.Content))

		//append the passwd or chap-passwd attrib
		if p.AuthType == "CHAP" {
			//append the user passwd
			attr.Type = ATTRTYPE_CHAPPASSWD
			attr.Content = p.ChapPassword
			attr.Length = uint8(len(attr.Content))
			p.Packet.AVPS = append(p.Packet.AVPS, attr)
			p.Packet.AuthMode = AUTHMODE_CHAP
		} else {
			//append the user passwd
			attr.Type = ATTRTYPE_PASSWD
			attr.Content = p.Password
			attr.Length = uint8(len(attr.Content))
			p.Packet.AVPS = append(p.Packet.AVPS, attr)
			p.Packet.AuthMode = AUTHMODE_PAP
		}
	}
	if reqType == PACKETTYPE_REQINFO {
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
	ret = true
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
func (p *PortalClient) SendReqAndRecvAckPkt(requType uint8) (ret bool) {
	//check the request type
	if (requType < PACKETTYPE_REQCHALLENGE) || (requType > PACKETTYPE_REQINFO) {
		logger.Error("request type invalid. ")
		return
	}
	var bRecvAck bool
	//It's not necessary to receive ack
	switch requType {
	case PACKETTYPE_AFFACKAUTH:
		bRecvAck = false
	case PACKETTYPE_ACKLOGOUT:
		bRecvAck = false
	case PACKETTYPE_REQLOGOUT:
		if p.Status == PCMSTATUS_CHALLENGE || p.Status == PCMSTATUS_AUTH {
			bRecvAck = false
		}
	default:
		bRecvAck = true
	}
	p.SerialNo = p.Packet.SerialNo
	p.ReqId = p.Packet.ReqID
	for ii := 0; ii < config.Cfg.RetryTime; ii++ {
		var err error
		//check whether we need receive ack packet
		if !bRecvAck {
			_, err = p.Send()
			if err != nil {
				logger.Error("send packet err:[%v], retry:%v", err, ii)
				continue
			}
			logger.Debug("need not receive ack packet.")
			ret = true
			break
		}

		var rbytes int
		rbytes, err = p.SendAndRecv()
		if err != nil {
			logger.Error("receive ack packet err:%v, retry:%v", rbytes, ii)
			continue
		}
		// recv len
		//GetMinPktLen
		if rbytes < p.Packet.GetMinPktLen() {
			logger.Error("receive ack packet too short. [%v]", rbytes)
			continue
		}
		//recv
		ret = true
		break
	}
	return
}

func (p *PortalClient) SendAndRecv() (size int, err error) {
	logger.Debug("udp:%v", p.BrasIP + ":" + util.ToString(config.Cfg.BrasPort))
	conn, e := net.Dial("udp",p.BrasIP + ":" + util.ToString(config.Cfg.BrasPort))
	defer conn.Close()
	if e != nil {
		err = e
		return
	}
	conn.SetReadDeadline(time.Now().Add(time.Duration(config.Cfg.Timeout)*time.Millisecond))
	conn.SetWriteDeadline(time.Now().Add(time.Duration(config.Cfg.Timeout)*time.Millisecond))
	logger.Debug("Begin to send packet.")

	size, err = conn.Write(p.Packet.Raw)
	if err != nil {
		logger.Error("send packet err:%v", err)
		return
	}
	if size <= 0 {
		logger.Error("send packet err size:%v", size)
		return
	}

	size, err = conn.Read(p.Packet.Raw[0:])
	if size >= 0 {
		p.Packet.PackageLen = size
	} else {
		p.Packet.PackageLen = 0
	}

	if err != nil {
		logger.Error("recv packet err:%v", err)
	}
	if size <= 0 {
		logger.Error("recv packet err size:%v", size)
	}
	return
}

func (p *PortalClient) Send() (size int, err error) {
	conn, e := net.Dial("udp", p.BrasIP + ":" + util.ToString(config.Cfg.BrasPort))
	defer conn.Close()
	if e != nil {
		err = e
		return
	}

	conn.SetWriteDeadline(time.Now().Add(time.Duration(config.Cfg.Timeout)*time.Millisecond))
	logger.Debug("Begin to send packet.")

	size, err = conn.Write(p.Packet.Raw)
	if err != nil {
		logger.Error("send packet err:%v", err)
	}
	if size <= 0 {
		logger.Error("send packet err size:%v", size)
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

func (p *PortalClient) GetUserErrCode() (userErrCode int32) {
	switch p.ErrCode {
	case PCMERR_OK:
		userErrCode = global.USER_RET_ERR_OK
	case PCMERR_UNKNOWN:
		userErrCode = global.USER_RET_ERR_UNKNOWN
	case PCMERR_CHALLENGEREFUSED:
		userErrCode = global.USER_RET_ERR_CHALLENGE_REFUSED
	case PCMERR_CONNECTCREATED:
		userErrCode = global.USER_RET_ERR_BAS_CONNECTCREATED
	case PCMERR_SAMEUSERAUTHING:
		userErrCode = global.USER_RET_ERR_BAS_SAMEUSERAUTHING
	case PCMERR_AUTHREFUSED:
		userErrCode = global.USER_RET_ERR_BAS_LOGIN_REFUSED
	case PCMERR_RECVTIMEOUT:
		userErrCode = global.USER_RET_ERR_SEND_FAILED
	case PCMERR_LOGOUTREFUSED:
		userErrCode = global.USER_RET_ERR_BAS_LOGOUT_REFUSED
	default:
		userErrCode = global.USER_RET_ERR_UNKNOWN
	}
	return
}