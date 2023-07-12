package tools

import (
	"bytes"
	"crypto/sha1"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"iatp/common/simplejson"
	"iatp/setting"
	"io/ioutil"
	"log"
	"math/rand"
	"net"
	"os"
	"path"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"go.mongodb.org/mongo-driver/bson/primitive"
)

// 计算传参sha1
func GetSha1s(s []string) string {
	str := strings.Join(s, "")
	r := sha1.Sum([]byte(str))
	return hex.EncodeToString(r[:])
}

// 获取文件夹下所有文件
func GetAllFiles(folder string, files *[]string) {
	rd, _ := ioutil.ReadDir(folder)
	for _, fi := range rd {
		if fi.IsDir() {
			GetAllFiles(folder+"/"+fi.Name(), files)
		} else {
			*files = append(*files, folder+"/"+fi.Name())
		}
	}
}

// 获取文件夹下所有文件 - WIN
func GetAllWinFiles(folder string, files *[]string) {
	rd, _ := ioutil.ReadDir(folder)
	for _, fi := range rd {
		if fi.IsDir() {
			GetAllWinFiles(folder+fi.Name()+"\\", files)
		} else {
			*files = append(*files, folder+"\\"+fi.Name())
		}
	}
}

// 获取文件夹下的所有文件夹
func GetAllPaths(folder string, paths *[]string) {
	rd, _ := ioutil.ReadDir(folder)
	for _, fi := range rd {
		if fi.IsDir() {
			*paths = append(*paths, folder+"/"+fi.Name())
			GetAllPaths(folder+"/"+fi.Name(), paths)
		}
	}
}

// datetime to unix
func DateTimeStr2Unix(dateTime string) int64 {
	t, _ := time.Parse(time.RFC3339, dateTime)
	return t.In(time.Local).Unix()
}

// unix to local datetime
func Unix2LocalDateTime(unixTime int64) string {
	return time.Unix(unixTime, 0).Format(time.RFC3339)
}

// UTC Time to Local Time
func UTCStr2LocalTimeStr(dateTime string) string {
	t, _ := time.Parse(time.RFC3339, dateTime)
	return t.In(time.Local).Format(time.RFC3339)
}

func UTCStr2LocalTime(dateTime string) time.Time {
	t, _ := time.Parse(time.RFC3339, dateTime)
	return t.In(time.Local)
}

// 获取所有高风险SPN
func GetAllHighRiskSpn() map[string]interface{} {
	val := setting.IatpSetting.ReadSet("high_risk_spn")

	highRiskSpn := make(map[string]interface{})

	if _, ok := val.(primitive.A); !ok {
		return nil
	}

	for _, v := range val.(primitive.A) {
		highRiskSpn[strings.ToLower(v.(string))] = nil
	}
	return highRiskSpn
}

// 获取map所有key
func GetAllKeyFromMap(m map[interface{}]interface{}) []interface{} {
	keys := make([]interface{}, 0, len(m))
	for k, _ := range m {
		keys = append(keys, k)
	}
	return keys
}

func Interface2String(v interface{}) string {
	if s, ok := v.(string); ok {
		return s
	} else {
		return ""
	}
}

// 去重
func RemoveDuplicateElement(list []string) []string {
	result := make([]string, 0, len(list))
	temp := map[string]struct{}{}
	for _, item := range list {
		if _, ok := temp[item]; !ok {
			temp[item] = struct{}{}
			result = append(result, item)
		}
	}
	return result
}

func IsContain(item interface{}, items ...interface{}) bool {
	for _, eachItem := range items {
		if eachItem == item {
			return true
		}
	}
	return false
}

func IsLikeContain(item string, items []string) bool {
	for _, eachItem := range items {
		if strings.Contains(eachItem, item) || strings.Contains(item, eachItem) {
			return true
		}
	}
	return false
}

// 检查目标IP是否在网段内
func CheckIPSegment(ip_segment string, target_ip net.IP) bool {
	ips := strings.Split(ip_segment, "-")
	if len(ips) != 2 {
		return false
	}

	start_ip := net.ParseIP(ips[0])
	end_ip := net.ParseIP(ips[1])

	if target_ip.To4() == nil {
		return false
	}

	if bytes.Compare(target_ip, start_ip) >= 0 && bytes.Compare(target_ip, end_ip) <= 0 {
		return true
	}

	return false
}

// 获取原始用户账户名
func GetRawUserName(cn string) string {
	if !strings.HasPrefix(cn, "CN") && !strings.HasPrefix(cn, "cn") {
		return cn
	} else {
		return strings.TrimLeft(strings.Split(cn, ",")[0], "CN=")
	}
}

// 获取当前项目路径
func GetCurrentPath() string {
	dir := getCurrentPathByExecutable()
	tmpDir, _ := filepath.EvalSymlinks(os.TempDir())
	if strings.Contains(dir, tmpDir) {
		return getCurrentPathByCaller()
	}
	return dir
}

// 获取当前执行文件绝对路径
func getCurrentPathByExecutable() string {
	exePath, err := os.Executable()
	if err != nil {
		log.Fatal(err)
	}
	res, _ := filepath.EvalSymlinks(filepath.Dir(exePath))
	return res
}

// 获取当前执行文件绝对路径（go run）
func getCurrentPathByCaller() string {
	var abPath string
	_, filename, _, ok := runtime.Caller(0)
	if ok {
		abPath = path.Dir(filename)
	}
	return abPath
}

var letters = []rune("0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ!@#$%^&")

// 获取指定位数的安全密码
func GetSecurityPasswd(passwd_len int) string {
	passwd := make([]rune, passwd_len)
	for i := range passwd {
		passwd[i] = letters[rand.Intn(len(letters))]
	}

	return string(passwd)
}

// 从json中以简易方式获取数据
func GetItemJson(event []byte, item string) string {
	if item == "" || item == "-" {
		return item
	}

	sj, err := simplejson.NewJson(event)
	if err != nil {
		fmt.Println(err)
		return item
	}

	items := strings.Split(item, ".")
	for _, v := range items[:len(items)-1] {
		sj = sj.Get(v)
	}

	return sj.Get(items[len(items)-1]).MustString()
}

// 字节转换成整型
func BytesToInt(b []byte) int {
	bytesBuffer := bytes.NewBuffer(b)

	var x int32
	binary.Read(bytesBuffer, binary.BigEndian, &x)

	return int(x)
}
