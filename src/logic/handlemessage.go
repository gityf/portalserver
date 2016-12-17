package logic

import (
	"context"
	"global"
	"config"
	logger "github.com/shengkehua/xlog4go"
)

func HandleMessage(msg *context.Message) (resp *context.BaseResponse) {

	switch msg.MessageType {
	case global.KMsgTypeLogin:
		resp = login(msg)
	case global.KMsgTypeLogout:
		resp = logout(msg)
	case global.KMsgTypeGetVlanInfo:
		resp = getVlanInfo(msg)
	default:
		resp = context.NewBaseResponse()
	}
	resp.ResponseJson(msg.Writer)
	return resp
}

func login(msg *context.Message)  (resp *context.BaseResponse) {
	portalClient := &PortalClient{
		BrasIP: msg.BrasIP,
		UserName: msg.UserName,
		Password: msg.Password,
		UserIP: msg.UserIP,
		AuthType: config.Cfg.AuthType,
	}
	logger.Debug("login Message:%v.", msg)
	logger.Debug("login portalClient brasip=%v,username=%v,password=%v,userip=%v.",
		portalClient.BrasIP, portalClient.UserName, portalClient.Password, portalClient.UserIP)
	resp = context.NewBaseResponse()
	if portalClient.ReqLogin() {
		resp.Errno = global.USER_RET_ERR_OK
	} else {
		resp.Errno = portalClient.GetUserErrCode()
	}
	resp.Errmsg = global.GetUserRetDesc(resp.Errno)
	resp.ResponseJson(msg.Writer)
	return resp
}

func logout(msg *context.Message)  (resp *context.BaseResponse) {
	portalClient := &PortalClient{
		BrasIP: msg.BrasIP,
		UserName: msg.UserName,
		UserIP: msg.UserIP,
	}
	resp = context.NewBaseResponse()
	if portalClient.ReqLogout() {
		resp.Errno = global.USER_RET_ERR_OK
	} else {
		resp.Errno = portalClient.GetUserErrCode()
	}
	resp.Errmsg = global.GetUserRetDesc(resp.Errno)
	resp.ResponseJson(msg.Writer)
	return resp
}

func getVlanInfo(msg *context.Message)  (resp *context.BaseResponse) {
	portalClient := &PortalClient{
		BrasIP: msg.BrasIP,
		UserName: msg.UserName,
		UserIP: msg.UserIP,
	}
	resp = context.NewBaseResponse()
	if portalClient.ReqVlaninfo() {
		resp.Errno = global.USER_RET_ERR_OK
	} else {
		resp.Errno = portalClient.GetUserErrCode()
	}
	resp.Errmsg = global.GetUserRetDesc(resp.Errno)
	resp.ResponseJson(msg.Writer)
	return resp
}