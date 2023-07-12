package smbshare

import (
	"fmt"
	"log"
	"net"

	smb2 "github.com/hirochachacha/go-smb2"
)

type SMBDir struct {
	UserName  string
	Password  string
	Server    string
	ShareName string
}

type File struct {
	FileName    string
	FilePath    string
	FileContext []byte
}

func NewSmbDir(user_name, password, server, share_name string) *SMBDir {
	return &SMBDir{
		UserName:  user_name,
		Password:  password,
		Server:    server,
		ShareName: share_name,
	}
}

func (s *SMBDir) ListFile(mount_dir string) (share_files []*File) {
	conn, err := net.Dial("tcp", s.Server)
	if err != nil {
		log.Println(err)
		return
	}
	defer conn.Close()

	d := &smb2.Dialer{
		Initiator: &smb2.NTLMInitiator{
			User:     s.UserName,
			Password: s.Password,
		},
	}

	ss, err := d.Dial(conn)
	if err != nil {
		log.Println(err)
		return
	}
	defer ss.Logoff()

	s_share, err := ss.Mount(s.ShareName)
	if err != nil {
		log.Println(err)
		return
	}

	share_files = make([]*File, 0)
	findFile(mount_dir, s_share, &share_files)

	return share_files
}

func findFile(file_path string, smb_share *smb2.Share, files *[]*File) {
	dir, err := smb_share.ReadDir(file_path)
	if err != nil {
		return
	}

	for _, v := range dir {
		if !v.IsDir() {
			// 发现共享文件

			// 读取共享文件内容
			context, _ := smb_share.ReadFile(fmt.Sprintf("%s\\%s", file_path, v.Name()))
			*files = append(*files, &File{
				FileName:    v.Name(),
				FilePath:    file_path,
				FileContext: context,
			})
		} else {
			findFile(fmt.Sprintf("%s\\%s", file_path, v.Name()), smb_share, files)
		}
	}
}
