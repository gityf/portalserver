package main

import (
	"net"
	"net/http"
	"global"
	"time"
	"sync/atomic"
)

var logFile = "./conf/log.json"
var confFile = "./conf/portalserver.json"

var reqchan = make(chan string, 1000000)

var logidGenerator LogId

var portalServerListener net.Listener
var httpServer http.Server

var uri2Handler map[string]*portalServerHandler


var portalServerQuit chan int
func init() {
	logidGenerator = LogId(time.Now().Unix())

	//安全退出
	portalServerQuit = make(chan int)

	uri2Handler = make(map[string]*portalServerHandler)

	uri2Handler["/portalserver/login"] = &portalServerHandler{Name: "Login", MessageType: global.KMsgTypeLogin, Callfunc: FuncHandler}
	uri2Handler["/portalserver/logout"] = &portalServerHandler{Name: "Logout", MessageType: global.KMsgTypeLogout, Callfunc: FuncHandler}
	uri2Handler["/portalserver/getvlaninfo"] = &portalServerHandler{Name: "GetVlaninfo", MessageType: global.KMsgTypeGetVlanInfo, Callfunc: FuncHandler}
	uri2Handler["/ping"] = &portalServerHandler{Name: "Ping", Callfunc: PingHandler}
	uri2Handler["/"] = &portalServerHandler{Name: "GetPortalServerInfo", Callfunc: StaticResource}
}

type LogId int64

func (i *LogId) GetNextId() int64 {
	return atomic.AddInt64((*int64)(i), 1)
}