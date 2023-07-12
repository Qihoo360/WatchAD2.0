package tools

import (
	"fmt"
	"io/ioutil"
	"os/exec"
)

func Crack(hash_modes string, hash string) string {
	cmd := exec.Command("/usr/bin/hashcat", "-m", hash_modes, hash, "/usr/share/wordlists/rockyou.txt", "-O")
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		fmt.Printf("命令执行输出通道创建失败: %v\n", err)
		return ""
	}
	defer stdout.Close()

	if err := cmd.Start(); err != nil {
		fmt.Printf("命令执行失败: %v\n", err)
		return ""
	}

	if result, err := ioutil.ReadAll(stdout); err != nil {
		fmt.Printf("结果读取失败: %v\n", err)
		return ""
	} else {
		return string(result)
	}
}
