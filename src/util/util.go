package util

import (
	"fmt"
	"reflect"
	"net"
	"strconv"
	"strings"
	"time"
	"bytes"
	"encoding/json"
)

func ToInt64(data interface{}) (res int64, err error) {
	val := reflect.ValueOf(data)
	switch data.(type) {
	case int, int8, int16, int32, int64:
		res = val.Int()
	case uint, uint8, uint16, uint32, uint64:
		res = int64(val.Uint())
	case float64:
		res = int64(data.(float64))
	case float32:
		res = int64(data.(float32))
	case string:
		res, err = strconv.ParseInt(strings.TrimSpace(data.(string)), 10, 64)
	case []byte:
		res, err = strconv.ParseInt(strings.TrimSpace(string(data.([]byte))), 10, 64)
	default:
		res, err = strconv.ParseInt(fmt.Sprintf("%v", data), 10, 64)
	}
	return
}

func ToInt32(data interface{}) (res int32, err error) {
	val := reflect.ValueOf(data)
	switch data.(type) {
	case int, int8, int16, int32, int64:
		res = int32(val.Int())
	case uint, uint8, uint16, uint32, uint64:
		res = int32(val.Uint())
	case float64:
		res = int32(data.(float64))
	case float32:
		res = int32(data.(float32))
	case string:
		res64, _ := strconv.ParseInt(strings.TrimSpace(data.(string)), 10, 64)
		res = int32(res64)
	case []byte:
		var res64 int64
		res64, err = strconv.ParseInt(strings.TrimSpace(string(data.([]byte))), 10, 64)
		res = int32(res64)
	default:
		var res64 int64
		res64, err = strconv.ParseInt(fmt.Sprintf("%v", data), 10, 64)
		res = int32(res64)
	}
	return
}

func ToUInt64(data interface{}) (res uint64, err error) {
	val := reflect.ValueOf(data)
	switch data.(type) {
	case int, int8, int16, int32, int64:
		res = uint64(val.Int())
	case uint, uint8, uint16, uint32, uint64:
		res = uint64(val.Uint())
	case float64:
		res = uint64(data.(float64))
	case float32:
		res = uint64(data.(float32))
	case string:
		res, err = strconv.ParseUint(strings.TrimSpace(data.(string)), 10, 64)
	case []byte:
		res, err = strconv.ParseUint(strings.TrimSpace(string(data.([]byte))), 10, 64)
	default:
		res, err = strconv.ParseUint(fmt.Sprintf("%v", data), 10, 64)
	}
	return
}

func ToInt(data interface{}) (res int, err error) {
	val := reflect.ValueOf(data)
	switch data.(type) {
	case int, int8, int16, int32, int64:
		res = int(val.Int())
	case uint, uint8, uint16, uint32, uint64:
		res = int(val.Uint())
	case float64:
		res = int(data.(float64))
	case float32:
		res = int(data.(float32))
	case string:
		res, err = strconv.Atoi(strings.TrimSpace(data.(string)))
	case []byte:
		res, err = strconv.Atoi(strings.TrimSpace(string(data.([]byte))))
	default:
		res, err = strconv.Atoi(fmt.Sprintf("%v", data))
	}
	return
}

func ToDateTime(data interface{}) (res time.Time, err error) {
	switch data.(type) {
	case []byte:
		res, err = time.ParseInLocation("2006-01-02 15:04:05", strings.TrimSpace(string(data.([]byte))), time.Local)
	case string:
		res, err = time.ParseInLocation("2006-01-02 15:04:05", strings.TrimSpace(data.(string)), time.Local)
	default:
		res, err = time.ParseInLocation("2006-01-02 15:04:05", fmt.Sprintf("%v", data), time.Local)
	}
	return
}

func ToDate(data interface{}) (res time.Time, err error) {
	switch data.(type) {
	case []byte:
		res, err = time.ParseInLocation("2006-01-02", strings.TrimSpace(string(data.([]byte))), time.Local)
	case string:
		res, err = time.ParseInLocation("2006-01-02", strings.TrimSpace(data.(string)), time.Local)
	default:
		res, err = time.ParseInLocation("2006-01-02", fmt.Sprintf("%v", data), time.Local)
	}
	return
}

func ToFloat32(data interface{}) (res float32, err error) {
	val := reflect.ValueOf(data)
	switch data.(type) {
	case int, int8, int16, int32, int64:
		res = float32(val.Int())
	case uint, uint8, uint16, uint32, uint64:
		res = float32(val.Uint())
	case float64:
		res = float32(data.(float64))
	case float32:
		res = data.(float32)
	case string:
		var res64 float64
		res64, err = strconv.ParseFloat(strings.TrimSpace(data.(string)), 32)
		res = float32(res64)
	default:
		var res64 float64
		res64, err = strconv.ParseFloat(fmt.Sprintf("%v", data), 32)
		res = float32(res64)
	}
	return
}

func ToFloat64(data interface{}) (res float64, err error) {
	val := reflect.ValueOf(data)
	switch data.(type) {
	case int, int8, int16, int32, int64:
		res = float64(val.Int())
	case uint, uint8, uint16, uint32, uint64:
		res = float64(val.Uint())
	case float64:
		res = data.(float64)
	case float32:
		res = float64(data.(float32))
	case string:
		res, err = strconv.ParseFloat(strings.TrimSpace(data.(string)), 64)
	default:
		res, err = strconv.ParseFloat(fmt.Sprintf("%v", data), 64)
	}
	return
}

func ToString(data interface{}) (res string) {
	switch v := data.(type) {
	case bool:
		res = strconv.FormatBool(v)
	case float32:
		res = strconv.FormatFloat(float64(v), 'f', 6, 32)
	case float64:
		res = strconv.FormatFloat(v, 'f', 6, 64)
	case int, int8, int16, int32, int64:
		val := reflect.ValueOf(data)
		res = strconv.FormatInt(int64(val.Int()), 10)
	case uint, uint8, uint16, uint32, uint64:
		val := reflect.ValueOf(data)
		res = strconv.FormatUint(uint64(val.Uint()), 10)
	case string:
		res = v
	case []byte:
		res = string(v)
	default:
		res = fmt.Sprintf("%v", v)
	}
	return
}

func AbsDiffFloat32(fa, fb float32) (res float32) {
	if fa >= fb {
		res = fa - fb
	} else {
		res = fb - fa
	}
	return
}

func DateTimeToString(dateTime time.Time) (dateTimeStr string) {
	return dateTime.Format("2006-01-02 15:04:05")
}

func DateToString(dateTime time.Time) (dateStr string) {
	return dateTime.Format("2006-01-02")
}

func EscapeStringBackslash(s string) string {
	/*reg := regexp.MustCompile(`('|"|-)`)
	rep := []byte("\\${1}")
	t := reg.ReplaceAll([]byte(s), rep)

	reg = regexp.MustCompile("(`)")
	t = reg.ReplaceAll(t, rep)

	return string(t)*/

	buf := []byte{}
	v := []byte(s)
	pos := len(buf)
	buf = reserveBuffer(buf, len(v)*2)

	for _, c := range v {
		switch c {
		case '\x00':
			buf[pos] = '\\'
			buf[pos+1] = '0'
			pos += 2
		case '\n':
			buf[pos] = '\\'
			buf[pos+1] = 'n'
			pos += 2
		case '\r':
			buf[pos] = '\\'
			buf[pos+1] = 'r'
			pos += 2
		case '\x1a':
			buf[pos] = '\\'
			buf[pos+1] = 'Z'
			pos += 2
		case '\'':
			buf[pos] = '\\'
			buf[pos+1] = '\''
			pos += 2
		case '-':
			buf[pos] = '\\'
			buf[pos+1] = '-'
			pos += 2
		case '"':
			buf[pos] = '\\'
			buf[pos+1] = '"'
			pos += 2
		case '\\':
			buf[pos] = '\\'
			buf[pos+1] = '\\'
			pos += 2
		default:
			buf[pos] = c
			pos++
		}
	}

	return string(buf[:pos])
}

// reserveBuffer checks cap(buf) and expand buffer to len(buf) + appendSize.
// If cap(buf) is not enough, reallocate new buffer.
func reserveBuffer(buf []byte, appendSize int) []byte {
	newSize := len(buf) + appendSize
	if cap(buf) < newSize {
		// Grow buffer exponentially
		newBuf := make([]byte, len(buf)*2+appendSize)
		copy(newBuf, buf)
		buf = newBuf
	}
	return buf[:newSize]
}

// snake string, XxYy to xx_yy
func SnakeString(s string) string {
	data := make([]byte, 0, len(s)*2)
	j := false
	num := len(s)
	for i := 0; i < num; i++ {
		d := s[i]
		if i > 0 && d >= 'A' && d <= 'Z' && j {
			data = append(data, '_')
		}
		if d != '_' {
			j = true
		}
		data = append(data, d)
	}
	return strings.ToLower(string(data[:]))
}

// camel string, xx_yy to XxYy
func CamelString(s string) string {
	data := make([]byte, 0, len(s))
	j := false
	k := false
	num := len(s) - 1
	for i := 0; i <= num; i++ {
		d := s[i]
		if k == false && d >= 'A' && d <= 'Z' {
			k = true
		}
		if d >= 'a' && d <= 'z' && (j || k == false) {
			d = d - 32
			j = false
			k = true
		}
		if k && d == '_' && num > i && s[i+1] >= 'a' && s[i+1] <= 'z' {
			j = true
			continue
		}
		data = append(data, d)
	}
	return string(data[:])
}

func GetLocalIPAddress() (localIp string, err error) {
	// Get local IP
	if addrs, err := net.InterfaceAddrs(); err == nil {
		for _, address := range addrs {
			if ipnet, ok := address.(*net.IPNet); ok && !ipnet.IP.IsLoopback() {
				if ipnet.IP.To4() != nil {
					localIp = ipnet.IP.String()
					break
				}
			}
		}
	}
	return
}

// out is pointer
func JsonDecode(in []byte, out interface{}) (err error) {
	decoder := json.NewDecoder(bytes.NewReader(in))
	decoder.UseNumber()
	err = decoder.Decode(out)
	return
}

func NowInS() int64 {
	return time.Now().Unix()
}

func NowInNs() int64 {
	return time.Now().UnixNano()
}

func NowInMs() int64 {
	return time.Now().UnixNano() / int64(time.Millisecond)
}