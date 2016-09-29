package main

import (
	"encoding/json"
	"time"
	"io"
	"fmt"
	"net/http"
	"runtime/debug"
	"sync"
	"strings"

	logger "github.com/shengkehua/xlog4go"
	"net/url"
	"reflect"
	"strconv"
	"global"
)

type HttpResponse struct {
	ErrNo  int       `json:"errno"`
	ErrMsg string    `json:"errmsg"`
	LogId  string    `json:"logid,omitempty"`
	Data   []*string `json:"data"`
}

type HttpResponser interface {
	//返回错误码, 用于监控
	ErrCode() int
	//返回内容给调用方
	ResponseJson(io.Writer) (int, error)
	//用于打印日志
	String() string
	//继承 error 接口
	Error() string
}

func (r *HttpResponse) ErrCode() int {
	return r.ErrNo
}

func (r *HttpResponse) ResponseJson(w io.Writer) (n int, err error) {
	var s []byte
	var s1 string
	s, err = json.Marshal(r)
	if err != nil {
		logger.Error("json.Marshal err:%v", err)
		s1 = fmt.Sprintf("{\"errno\":%v,\"errmsg\":\"%v\",\"logid\":\"%v\"}", global.ERR_JSON_MARSHAL_FAILED, err, r.LogId)
	} else {
		s1 = string(s)
	}
	n, err = io.WriteString(w, s1)
	if err != nil {
		logger.Error("io.WriteString err:%v", err)
	}
	return
}

func (r *HttpResponse) Error() string {
	return fmt.Sprintf("errno=%v,errmsg=%v", r.ErrNo, r.ErrMsg)
}

func (r *HttpResponse) String() string {
	resJson, _ := json.Marshal(r)
	return string(resJson)
}

func doErrorResponse(logid string, errno int, errmsg string, writer io.Writer) HttpResponser {
	return doResponse(logid, errno, errmsg, writer)
}


func doResponse(logid string, errno int, errmsg string, writer io.Writer) (r HttpResponser) {
	r = &HttpResponse{
		ErrNo:  errno,
		ErrMsg: errmsg,
		LogId:  logid,
	}
	_, err := r.ResponseJson(writer)
	if err != nil {
		logger.Error("doResponse err:%v", err)
	}
	return
}

type portalServerHandler struct {
	Name     string
	MessageType uint64
	Callfunc func(w http.ResponseWriter, r *http.Request, logId int64, messageType uint64) HttpResponser

	wg sync.WaitGroup
}

func (portalServerH *portalServerHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	var logId int64
	var resp HttpResponser
	var errCode int
	var info map[string]interface{}

	tBegin := time.Now()	
	portalServerH.wg.Add(1)
	
	defer func () {
		portalServerH.wg.Done()
		//耗时
		latency := time.Since(tBegin)
		if resp != nil {
			errCode = resp.ErrCode()
		}else{
			//unlikely
			errCode = -1
		}
		//捕捉panic
		if err := recover(); err != nil {
			errCode = global.ERR_PANIC
			logger.Error("LogId:%d HandleError# recover errno:%d stack:%s", logId, errCode, string(debug.Stack()))
		}
		logger.Warn("%v, cost:%v", info, latency)
	}()

	logId = logidGenerator.GetNextId()
	r.ParseForm()
	info = GetHttpRequestInfo(r)
	resp = portalServerH.Callfunc(w, r, logId, portalServerH.MessageType)
	return
}

func GetHttpRequestInfo(r *http.Request) (info map[string]interface{}) {
	info = make(map[string]interface{})
	info["url"] = r.URL.Path
	info["param"] = r.Form
	info["host"] = r.Host
	info["remote"]=r.RemoteAddr
	s1 := strings.Split(r.URL.Path, "/")
	if len(s1) > 0 {
		info["name"] = s1[len(s1)-1]
	} else {
		info["name"] = "NoBody"
	}
	info["now"]=time.Now()
	return
}

func (portalServerH *portalServerHandler) Close() {
	portalServerH.wg.Wait()
}

func isStructPtr(t reflect.Type) bool {
	return t.Kind() == reflect.Ptr && t.Elem().Kind() == reflect.Struct
}

var sliceOfInts = reflect.TypeOf([]int(nil))
var sliceOfStrings = reflect.TypeOf([]string(nil))

// Input returns the input data map from POST or PUT request body and query string.
func Input(r *http.Request) url.Values {
	if r.Form == nil {
		r.ParseForm()
	}
	return r.Form
}

// parse form values to struct via tag.
func ParseForm(form url.Values, obj interface{}) error {
	objT := reflect.TypeOf(obj)
	objV := reflect.ValueOf(obj)
	if !isStructPtr(objT) {
		return fmt.Errorf("%v must be  a struct pointer", obj)
	}
	objT = objT.Elem()
	objV = objV.Elem()

	for i := 0; i < objT.NumField(); i++ {
		fieldV := objV.Field(i)
		if !fieldV.CanSet() {
			continue
		}

		fieldT := objT.Field(i)
		tags := strings.Split(fieldT.Tag.Get("json"), ",")
		var tag string
		if len(tags) == 0 || len(tags[0]) == 0 {
			tag = fieldT.Name
		} else if tags[0] == "-" {
			continue
		} else {
			tag = tags[0]
		}

		value := form.Get(tag)
		if len(value) == 0 {
			continue
		}

		switch fieldT.Type.Kind() {
		case reflect.Bool:
			if strings.ToLower(value) == "on" || strings.ToLower(value) == "1" || strings.ToLower(value) == "yes" {
				fieldV.SetBool(true)
				continue
			}
			if strings.ToLower(value) == "off" || strings.ToLower(value) == "0" || strings.ToLower(value) == "no" {
				fieldV.SetBool(false)
				continue
			}
			b, err := strconv.ParseBool(value)
			if err != nil {
				return err
			}
			fieldV.SetBool(b)
		case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
			x, err := strconv.ParseInt(value, 10, 64)
			if err != nil {
				return err
			}
			fieldV.SetInt(x)
		case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
			x, err := strconv.ParseUint(value, 10, 64)
			if err != nil {
				return err
			}
			fieldV.SetUint(x)
		case reflect.Float32, reflect.Float64:
			x, err := strconv.ParseFloat(value, 64)
			if err != nil {
				return err
			}
			fieldV.SetFloat(x)
		case reflect.Interface:
			fieldV.Set(reflect.ValueOf(value))
		case reflect.String:
			fieldV.SetString(value)
		case reflect.Struct:
			switch fieldT.Type.String() {
			case "time.Time":
				format := time.RFC3339
				if len(tags) > 1 {
					format = tags[1]
				}
				t, err := time.Parse(format, value)
				if err != nil {
					return err
				}
				fieldV.Set(reflect.ValueOf(t))
			}
		case reflect.Slice:
			if fieldT.Type == sliceOfInts {
				formVals := form[tag]
				fieldV.Set(reflect.MakeSlice(reflect.SliceOf(reflect.TypeOf(int(1))), len(formVals), len(formVals)))
				for i := 0; i < len(formVals); i++ {
					val, err := strconv.Atoi(formVals[i])
					if err != nil {
						return err
					}
					fieldV.Index(i).SetInt(int64(val))
				}
			} else if fieldT.Type == sliceOfStrings {
				formVals := form[tag]
				fieldV.Set(reflect.MakeSlice(reflect.SliceOf(reflect.TypeOf("")), len(formVals), len(formVals)))
				for i := 0; i < len(formVals); i++ {
					fieldV.Index(i).SetString(formVals[i])
				}
			}
		}
	}
	return nil
}