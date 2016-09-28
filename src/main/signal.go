package main

/*
   中断信号的捕获函数
*/
import (
	logger "github.com/shengkehua/xlog4go"
	"os"
	"os/signal"
	"syscall"
)

func signal_proc() {

	c := make(chan os.Signal, 1)

	signal.Notify(c, syscall.SIGINT, syscall.SIGALRM, syscall.SIGTERM, syscall.SIGUSR1)

	// Block until a signal is received.
	sig := <-c

	logger.Warn("Signal received: %v", sig)

	portalServerListener.Close()

	for _, handler := range uri2Handler {
		handler.Close()
	}

	logger.Warn("send quit signal")
	portalServerQuit <- 1
}
