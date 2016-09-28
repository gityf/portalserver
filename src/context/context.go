package context

import (
	"fmt"
	"io"
	"encoding/json"
	logger "github.com/shengkehua/xlog4go"
	"global"
	"net/http"
)

type BaseResponse struct {
	Errno  int32  `json:"errno"`
	Errmsg string `json:"errmsg"`
}

func DoResponse(result interface{}, w io.Writer) (n int, err error) {
	var resJson []byte
	switch result.(type) {
	case *BaseResponse:
		resJson, err = json.Marshal(result.(*BaseResponse))
	default:
	}

	var s1 string
	if err != nil {
		logger.Error("json.Marshal err:%v", err)
		s1 = fmt.Sprintf("{\"errno\":%v,\"errmsg\":\"%v\"}",
			global.ERR_JSON_MARSHAL_FAILED, err)
	}else{
		s1 = string(resJson)
	}

	n, err = io.WriteString(w, s1)
	if err != nil {
		logger.Error("io.WriteString err:%v", err)
	}

	return
}

func NewBaseResponse() *BaseResponse {
	var br BaseResponse
	br.Errno = 0
	br.Errmsg = "ok"
	return &br
}

func (r *BaseResponse) ErrCode() int {
	return int(r.Errno)
}

func (r *BaseResponse) ResponseJson(w io.Writer) (n int, err error) {
	n, err = DoResponse(r, w)
	return
}

func (r *BaseResponse) String() string {
	resJson, _ := json.Marshal(r)
	return string(resJson)
}

func (r *BaseResponse) Error() string {
	return r.Errmsg
}

type FormStruct struct {
	UserName string `json:"user_name"`
	Password string `json:"password"`
	BrasIP   string `json:"bras_ip"`
	FrameIP  string `json:"frame_ip"`
	UserMac  string `json:"user_mac"`
}

type Message struct {
	ClientLogId string              //客户端日志id
	LogId       int64               //本地日志id
	Source      string              //客户端的来源
	Writer      http.ResponseWriter //http响应object
	MessageType uint64
	*FormStruct
}