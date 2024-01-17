/*
Copyright © 2021 NAME HERE <EMAIL ADDRESS>

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

	http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/
package cmd

import (
	"fmt"
	"iatp/common/domain"
	"iatp/iatp_wbm/repositories"
	"iatp/setting"

	"github.com/spf13/cobra"
	"go.mongodb.org/mongo-driver/bson"
)

var (
	authdomain string
	user       string
)

// webCmd represents the web command
var webCmd = &cobra.Command{
	Use:   "web",
	Short: "Web management related Settings",
	Long: `Web management related Settings. For example:

`,
	Run: func(cmd *cobra.Command, args []string) {
		if init, _ := cmd.Flags().GetBool("init"); init {
			// 初始化配置
			d, err := domain.NewDomain(authdomain)
			if err != nil {
				fmt.Printf("[-]认证域配置失败:%s\n", err.Error())
			}

			var set setting.Setting

			if err := setting.SettingsMongo.FindOne(bson.M{
				"name": "auth_domain",
			}).Decode(&set); err != nil {
				setting.SettingsMongo.InsertOne(setting.Setting{
					Name:        "auth_domain",
					Value:       d.DomainName,
					Description: "认证域",
				})
			} else {
				setting.SettingsMongo.UpdateOne(bson.M{"name": "auth_domain"}, bson.M{
					"$set": bson.M{
						"value": d.DomainName,
					},
				})
			}
			// 用户是否存在域中校验
			if !d.IsExistUser(user) {
				fmt.Println("[-]新增用户失败：请检查域内是否存在此用户")
			} else {
				if !repositories.NewUserRepository().InsertOne(user) {
					fmt.Println("[-]新增用户失败：数据库中已存在此用户")
				}
			}
		}
	},
}

func init() {
	rootCmd.AddCommand(webCmd)

	webCmd.Flags().Bool("init", false, "Initialize web Settings.")
	webCmd.Flags().StringVar(&authdomain, "authdomain", "", "Web authentication domain.")
	webCmd.Flags().StringVar(&user, "user", "", "Web authentication domain user.")

	// Here you will define your flags and configuration settings.

	// Cobra supports Persistent Flags which will work for this command
	// and all subcommands, e.g.:
	// webCmd.PersistentFlags().String("foo", "", "A help for foo")

	// Cobra supports local flags which will only run when this command
	// is called directly, e.g.:
	// webCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")
}
