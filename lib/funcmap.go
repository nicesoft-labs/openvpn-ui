package lib

import (
	"bytes"
	"encoding/json"
	"fmt"
	"html/template"
	"strconv"
	"time"

	"github.com/beego/beego/v2/core/logs"
	"github.com/beego/beego/v2/server/web"
)

// AddFuncMaps .
func AddFuncMaps() {
	_ = web.AddFuncMap("field_error_message", func(v map[string]map[string]string, key string) map[string]string {
		if val, ok := v[key]; ok {
			return val
		}
		return make(map[string]string)
	})
	_ = web.AddFuncMap("field_error_exist", func(v map[string]map[string]string, key string) bool {
		if _, ok := v[key]; ok {
			return true
		}
		return false
	})
	_ = web.AddFuncMap("printkb", func(i interface{}) string {
		switch v := i.(type) {
		case uint64:
			return num2str(int64(i.(uint64)/1024), '\u00A0')
		case int64:
			return num2str(i.(int64)/1024, '\u00A0')
		default:
			logs.Error("Unknown type:", v)
		}
		return "Mapping error"
	})
	_ = web.AddFuncMap("printmb", func(i interface{}) string {
		switch v := i.(type) {
		case uint64:
			return num2str(int64(i.(uint64)/1024/1024), '\u00A0')
		case int64:
			return num2str(i.(int64)/1024/1024, '\u00A0')
		default:
			logs.Error("Unknown type:", v)
		}
		return "Mapping error"
	})
	_ = web.AddFuncMap("printmbold", func(i uint64) string {
		return num2str(int64(i/1024/1024), ' ')
	})
	_ = web.AddFuncMap("printgb", func(i uint64) string {
		return num2str(int64(i/1024/1024/1024), ' ')
	})
	_ = web.AddFuncMap("percent", func(x, y interface{}) string {
		//logs.Notice("Percent", x, y)
		zValue := "0"
		switch v := x.(type) {
		case string:
			logs.Error("Not implemented")
		case int32:
			if x.(int32) == 0 || y.(int32) == 0 {
				return zValue
			}
			a := float64(x.(int32))
			b := float64(y.(int32))
			return fmt.Sprintf("%d", int((a/b)*float64(100)))
		case int64:
			if x.(int64) == 0 || y.(int64) == 0 {
				return zValue
			}
			a := float64(x.(int64))
			b := float64(y.(int64))
			return fmt.Sprintf("%d", int((a/b)*float64(100)))
		case uint64:
			if x.(uint64) == 0 || y.(uint64) == 0 {
				return zValue
			}
			a := float64(x.(uint64))
			b := float64(y.(uint64))
			return fmt.Sprintf("%d", int((a/b)*float64(100)))
		default:
			logs.Error("Unknown type:", v)
		}
		return "Mapping error"
	})
	_ = web.AddFuncMap("tojson", func(v interface{}) template.JS {
		data, err := json.Marshal(v)
		if err != nil {
			logs.Error("json marshal", err)
			return template.JS("{}")
		}
		return template.JS(data)
	})
	_ = web.AddFuncMap("divMB", func(bytesIn interface{}, bytesOut interface{}) float64 {
		var inVal, outVal uint64
		switch v := bytesIn.(type) {
		case uint64:
			inVal = v
		case int64:
			inVal = uint64(v)
		}
		switch v := bytesOut.(type) {
		case uint64:
			outVal = v
		case int64:
			outVal = uint64(v)
		}
		return float64(inVal+outVal) / 1024.0 / 1024.0
	})
	_ = web.AddFuncMap("divMB64", func(total interface{}) float64 {
		switch v := total.(type) {
		case int64:
			return float64(v) / 1024.0 / 1024.0
		case uint64:
			return float64(v) / 1024.0 / 1024.0
		default:
			return 0
		}
	})
	_ = web.AddFuncMap("divGiB", func(bytesIn interface{}, bytesOut interface{}) float64 {
		var inVal, outVal uint64
		switch v := bytesIn.(type) {
		case uint64:
			inVal = v
		case int64:
			inVal = uint64(v)
		}
		switch v := bytesOut.(type) {
		case uint64:
			outVal = v
		case int64:
			outVal = uint64(v)
		}
		return float64(inVal+outVal) / 1024.0 / 1024.0 / 1024.0
	})
	_ = web.AddFuncMap("formatDuration", func(sec interface{}) string {
		var total int64
		switch v := sec.(type) {
		case int64:
			total = v
		case uint64:
			total = int64(v)
		}
		if total < 60 {
			return fmt.Sprintf("%ds", total)
		}
		minutes := total / 60
		hours := minutes / 60
		if hours > 0 {
			return fmt.Sprintf("%dh %02dm", hours, minutes%60)
		}
		return fmt.Sprintf("%dm", minutes)
	})
	_ = web.AddFuncMap("formatTsInt", func(ts interface{}) string {
		var val int64
		switch v := ts.(type) {
		case int64:
			val = v
		case uint64:
			val = int64(v)
		}
		if val == 0 {
			return ""
		}
		return time.Unix(val, 0).UTC().Format(time.RFC3339)
	})
}

func num2str(n int64, sep rune) string {
	s := strconv.FormatInt(n, 10)
	startOffset := 0
	var buff bytes.Buffer
	if n < 0 {
		startOffset = 1
		buff.WriteByte('-')
	}
	l := len(s)
	commaIndex := 3 - ((l - startOffset) % 3)
	if commaIndex == 3 {
		commaIndex = 0
	}
	for i := startOffset; i < l; i++ {
		if commaIndex == 3 {
			buff.WriteRune(sep)
			commaIndex = 0
		}
		commaIndex++
		buff.WriteByte(s[i])
	}
	return buff.String()
}
