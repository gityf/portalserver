package util

import (
	"testing"
	"time"
	"fmt"
)

func TestTransToString(t *testing.T) {
	if string("123") != ToString(int(123)) {
		t.Error("int to string err.")
	}
	if string("123") != ToString(int64(123)) {
		t.Error("int64 to string err.")
	}
	if string("123") != ToString(uint(123)) {
		t.Error("uint to string err.")
	}
	if string("123") != ToString(uint64(123)) {
		t.Error("uint64 to string err.")
	}
	if string("123") != ToString(uint32(123)) {
		t.Error("uint32 to string err.")
	}
	if string("123.123459") != ToString(float32(123.123456)) {
		t.Errorf("float32 to string err:%v.", ToString(float32(123.123456)))
	}
	if string("123.123456") != ToString(float64(123.123456)) {
		t.Errorf("float64 to string err:%v.", ToString(float32(123.123456)))
	}
	if string("123") != ToString(string("123")) {
		t.Error("string to string err.")
	}
	if string("123") != ToString([]byte("123")) {
		t.Error("[]byte to string err.")
	}
}

func TestTransToUInt64(t *testing.T) {
	val, _ := ToUInt64(int(123))
	if uint64(123) != val {
		t.Error("int to string err.")
	}
	val1, _ := ToUInt64(int64(123))
	if uint64(123) != val1 {
		t.Error("int64 to string err.")
	}
	val2, _ := ToUInt64(uint(123))
	if uint64(123) != val2 {
		t.Error("uint to string err.")
	}
	val3, _ := ToUInt64(uint64(123))
	if uint64(123) != val3 {
		t.Error("uint64 to string err.")
	}
	val4, _ := ToUInt64(uint32(123))
	if uint64(123) != val4 {
		t.Error("uint32 to string err.")
	}
	val5, _ := ToUInt64(float32(123.123456))
	if uint64(123) != val5 {
		t.Errorf("float32 to string err:%v.", val5)
	}
	//Warning, too large number
	val6, _ := ToUInt64(float64(4611615694780401600))
	if uint64(4611615694780401600) != val6 {
		t.Errorf("float64 to string err:%v.", val6)
	}
	val7, _ := ToUInt64(string("123"))
	if uint64(123) != val7 {
		t.Error("string to string err.")
	}
	val8, _ := ToUInt64([]byte("123"))
	if uint64(123) != val8 {
		t.Error("string to string err.")
	}
	val9, _ := ToUInt64([]byte("4611615694780401600"))
	if uint64(4611615694780401600) != val9 {
		t.Error("string to string err.")
	}

}

func TestTransDateTime(t *testing.T) {
	var dateTime time.Time
	dateTime, _ = ToDateTime(string("2016-06-16 12:34:56"))
	if string("2016-06-16 12:34:56") != DateTimeToString(dateTime) {
		t.Errorf("DateTimeToString:%v, TransToDateTime:%v err", DateTimeToString(dateTime), dateTime)
	}
	dateTime, _ = ToDateTime([]byte("2016-06-16 12:34:56"))
	if string("2016-06-16 12:34:56") != DateTimeToString(dateTime) {
		t.Errorf("DateTimeToString:%v, TransToDateTime:%v err", DateTimeToString(dateTime), dateTime)
	}
	var dateDate time.Time
	dateDate, _ = ToDate(string("2016-06-16"))
	if string("2016-06-16") != DateToString(dateDate) {
		t.Errorf("DateToString:%v, TransToDate:%v err", DateToString(dateDate), dateDate)
	}
}

func TestSnakeString(t *testing.T) {
	if string("xx_yy") != SnakeString("XxYy") {
		t.Errorf("expect xx_yy , SnakeString:%v", SnakeString("XxYy"))
	}
}

func TestCamelString(t *testing.T) {
	if string("XxYy") != CamelString("xx_yy") {
		t.Errorf("expect XxYy , CamelString:%v", CamelString("xx_yy"))
	}
}