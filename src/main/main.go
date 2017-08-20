package main

import (
	"config"
	"fmt"
	"net"
	"net/http"
	_ "net/http/pprof"
	"os"
	"path"
	"runtime"
	"runtime/debug"

	logger "github.com/xlog4go"
	"global"
	"util"
)

func main() {
	runtime.GOMAXPROCS(runtime.NumCPU())
	dirPath := path.Dir(os.Args[0])
	logFile = dirPath + "/../" + logFile
	confFile = dirPath + "/../" + confFile
	fmt.Println("logFile:", logFile)
	fmt.Println("confFile:", confFile)
	var err error
	if err = config.ParseConf(confFile); err != nil {
		fmt.Println("conf init fail: %s", err.Error())
		return
	}

	// init log
	if err = logger.SetupLogWithConf(logFile); err != nil {
		fmt.Println("log init fail: %s", err.Error())
		return
	}
	defer logger.Close()

	// set recover
	defer func() {
		if err := recover(); err != nil {
			logger.Error("abort, unknown error, errno:%d,errmsg:%v, stack:%s",
				global.ERR_PANIC, err, string(debug.Stack()))
		}
	}()

	fmt.Println(config.Cfg)
	logger.Info("%v", config.Cfg)

	//register signal proc
	go signal_proc()

	//start pprof monitor
	go func() {
		err := http.ListenAndServe(":"+util.ToString(config.Cfg.PprofPort), nil)
		if err != nil {
			logger.Error("failed to start pprof monitor:%s", err.Error())
		}
	}()

	// start http server

	logger.Info("init Httpserver")

	mux := http.NewServeMux()

	for uri, handler := range uri2Handler {
		mux.Handle(uri, handler)
	}

	portalServerListener, err = net.Listen("tcp", ":"+util.ToString(config.Cfg.Port))
	defer portalServerListener.Close()
	if err != nil {
		logger.Error("tcp listen fail: %s", err.Error())
	}
	fmt.Printf("portalServer starting ok at port:%v.\n", config.Cfg.Port)

	httpServer = http.Server{Handler: mux}
	err = httpServer.Serve(portalServerListener)

	logger.Error("http listen fail: %s", err.Error())

	value := <-portalServerQuit
	logger.Info("portalServer quit:%d", value)
	fmt.Println("portalServer stopping...")
}
