package main

/*
   worker的实现罗辑
*/
import (
	logger "github.com/xlog4go"
)

func worker() {
	for {
		select {
		case k := <-reqchan:
			logger.Info("worker get: " + k)
		}
	}
}
