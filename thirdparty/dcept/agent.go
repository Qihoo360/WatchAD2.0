package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"os"
	"runtime"
	"syscall"
	"time"
	"unsafe"

	"github.com/kardianos/service"
	host "github.com/shirou/gopsutil/v3/host"
	"gopkg.in/yaml.v2"
)

var (
	advapi                  = syscall.NewLazyDLL("advapi32.dll")
	createProcessWithLogonW = advapi.NewProc("CreateProcessWithLogonW")
)

const (
	// Use only network credentials for login
	LOGON_NETCREDENTIALS_ONLY uint32 = 0x00000002
	// The new process does not inherit the error mode of the calling process.
	// Instead, CreateProcessWithLogonW gives the new process the current
	// default error mode.
	CREATE_DEFAULT_ERROR_MODE uint32 = 0x04000000
	// Flag parameter that indicates to use the value set in ShowWindow
	STARTF_USESHOWWINDOW = 0x00000001
	// Tell windows not to show the window
	ShowWindow = 0

	CREATE_SUSPENDED uint32 = 0x00000004
)

var (
	Info  *log.Logger
	Error *log.Logger
)

type APIResp struct {
	Code     string `json:"code"`
	Message  string `json:"message"`
	Password string `json:"password"`
}

type AgentConfig struct {
	Api    string `yaml:"api"`
	Domain string `yaml:"domain"`
}

func (c *AgentConfig) GetConf(configPath string) *AgentConfig {
	yamlFile, err := ioutil.ReadFile(configPath)
	if err != nil {
		Error.Printf("配置文件加载失败: %v\n", err)
	}
	err = yaml.Unmarshal(yamlFile, c)
	if err != nil {
		Error.Printf("配置文件解析失败: %v\n", err)
	}
	return c
}

func CreateProcessWithLogonW(
	username *uint16,
	domain *uint16,
	password *uint16,
	logonFlags uint32,
	applicationName *uint16,
	commandLine *uint16,
	creationFlags uint32,
	environment *uint16,
	currentDirectory *uint16,
	startupInfo *syscall.StartupInfo,
	processInformation *syscall.ProcessInformation,
) error {
	r1, _, err := createProcessWithLogonW.Call(
		uintptr(unsafe.Pointer(username)),
		uintptr(unsafe.Pointer(domain)),
		uintptr(unsafe.Pointer(password)),
		uintptr(logonFlags),
		uintptr(unsafe.Pointer(applicationName)),
		uintptr(unsafe.Pointer(commandLine)),
		uintptr(creationFlags),
		uintptr(unsafe.Pointer(environment)),
		uintptr(unsafe.Pointer(currentDirectory)),
		uintptr(unsafe.Pointer(startupInfo)),
		uintptr(unsafe.Pointer(processInformation)),
	)

	runtime.KeepAlive(username)
	runtime.KeepAlive(domain)
	runtime.KeepAlive(password)
	runtime.KeepAlive(applicationName)
	runtime.KeepAlive(commandLine)
	runtime.KeepAlive(environment)
	runtime.KeepAlive(currentDirectory)
	runtime.KeepAlive(startupInfo)
	runtime.KeepAlive(processInformation)

	if int(r1) == 0 {
		return os.NewSyscallError("CreateProcessWithLogonW", err)
	}
	return nil
}

func ListToEnvironmentBlock(list *[]string) *uint16 {
	if list == nil {
		return nil
	}

	size := 1
	for _, v := range *list {
		size += len(syscall.StringToUTF16(v))
	}

	result := make([]uint16, size)

	tail := 0

	for _, v := range *list {
		uline := syscall.StringToUTF16(v)
		copy(result[tail:], uline)
		tail += len(uline)
	}

	result[tail] = 0

	return &result[0]
}

// 注入凭证
func injectCred(user, dm, pw string) uint32 {
	path := "C:\\WINDOWS\\notepad.exe"

	username := syscall.StringToUTF16Ptr(user)
	password := syscall.StringToUTF16Ptr(pw)
	domain := syscall.StringToUTF16Ptr(dm)
	logonFlags := LOGON_NETCREDENTIALS_ONLY
	applicationName := syscall.StringToUTF16Ptr(path)
	commandLine := syscall.StringToUTF16Ptr(``)
	creationFlags := CREATE_DEFAULT_ERROR_MODE
	environment := ListToEnvironmentBlock(nil)
	currentDirectory := syscall.StringToUTF16Ptr(`C:\`)

	startupInfo := &syscall.StartupInfo{}
	startupInfo.ShowWindow = ShowWindow
	startupInfo.Flags = startupInfo.Flags | STARTF_USESHOWWINDOW
	processInfo := &syscall.ProcessInformation{}

	_ = CreateProcessWithLogonW(
		username,
		domain,
		password,
		logonFlags,
		applicationName,
		commandLine,
		creationFlags,
		environment,
		currentDirectory,
		startupInfo,
		processInfo)

	return processInfo.ProcessId
}

func getOSVersion() string {
	platform, _, version, _ := host.PlatformInformation()
	return fmt.Sprintf("%s-%s", platform, version)
}

func postAPI(api_host, hostname, os_version, domainname string) ([]byte, error) {
	data := make(url.Values)
	data["hostname"] = []string{hostname}
	data["os_version"] = []string{os_version}
	data["domain"] = []string{domainname}

	res, err := http.PostForm(fmt.Sprintf("http://%s/honeypot/registered", api_host), data)
	if err != nil {
		return []byte{}, err
	}
	defer res.Body.Close()

	body, readErr := ioutil.ReadAll(res.Body)
	if readErr != nil {
		return []byte{}, readErr
	} else {
		return body, nil
	}
}

var (
	configPath = flag.String("c", "", "配置文件位置")
	logPath    = flag.String("l", "", "日志文件夹路径")
	config     *AgentConfig
)

type program struct{}

func (p *program) Start(s service.Service) error {
	go p.run()
	return nil
}

func (p *program) run() {
	// 主机名
	host_name, _ := os.Hostname()

	// 系统版本
	os_version := getOSVersion()

	for {
		Info.Println("调用API请求开始")
		resp, err := postAPI(config.Api, host_name, os_version, config.Domain)
		if err != nil {
			Error.Printf("API 请求异常: %v\n", err)
			time.Sleep(5 * 60 * time.Second)
			continue
		}

		var apiResp APIResp
		err = json.Unmarshal(resp, &apiResp)
		if err != nil {
			Error.Printf("json 解析异常: %v\n", err)
			time.Sleep(5 * 60 * time.Second)
			continue
		}

		if apiResp.Code != "0" {
			Error.Printf("API响应异常: %v \n", apiResp.Message)
			time.Sleep(5 * 60 * time.Second)
			continue
		}

		Info.Println("注入进程")
		processID := injectCred("Administrator", config.Domain, apiResp.Password)
		time.Sleep(24 * time.Hour)

		process, err := os.FindProcess(int(processID))
		if err != nil {
			Error.Printf("Process 获取异常: %v\n", err)
		}

		err = process.Kill()
		if err != nil {
			Error.Printf("Process Kill异常: %v\n", err)
		}
	}
}

func (p *program) Stop(s service.Service) error {
	return nil
}

func main() {
	flag.Parse()

	if *configPath == "" {
		log.Panic("需要指定配置文件路径")
	}

	config = &AgentConfig{}
	config = config.GetConf(*configPath)

	if config.Api == "" || config.Domain == "" {
		log.Panic("配置文件错误,参数需要都不为空")
	}

	if *logPath != "" {
		//日志输出文件
		file, err := os.OpenFile(fmt.Sprintf("%s\\sys.log", *logPath), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
		if err != nil {
			log.Fatalln("Faild to open error logger file:", err)
		}
		//自定义日志格式
		Info = log.New(io.MultiWriter(file, os.Stderr), "INFO: ", log.Ldate|log.Ltime|log.Lshortfile)
		Error = log.New(io.MultiWriter(file, os.Stderr), "ERROR: ", log.Ldate|log.Ltime|log.Lshortfile)
	} else {
		//日志输出文件
		file, err := os.OpenFile("sys.log", os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
		if err != nil {
			log.Fatalln("Faild to open error logger file:", err)
		}
		//自定义日志格式
		Info = log.New(io.MultiWriter(file, os.Stderr), "INFO: ", log.Ldate|log.Ltime|log.Lshortfile)
		Error = log.New(io.MultiWriter(file, os.Stderr), "ERROR: ", log.Ldate|log.Ltime|log.Lshortfile)
	}

	svcConfig := &service.Config{
		Name:        "agent",
		DisplayName: "agent",
		Description: "",
	}

	prg := &program{}
	s, err := service.New(prg, svcConfig)
	if err != nil {

	}

	if err = s.Run(); err != nil {
		log.Fatal(err)
	}
}
