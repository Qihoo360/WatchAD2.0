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
	"iatp/iatp"
	wbm "iatp/iatp_wbm"

	"github.com/spf13/cobra"
)

// runCmd represents the run command
var runCmd = &cobra.Command{
	Use:   "run",
	Short: "Execute Threat Hunt",
	Long: `Start detection to identify threat attacks. For example:

`,
	Run: func(cmd *cobra.Command, args []string) {
		engine_start, _ := cmd.Flags().GetBool("engine_start")
		web_start, _ := cmd.Flags().GetBool("web_start")

		if engine_start {
			iatp.Start()
		}

		if web_start {
			wbm.Run()
		}

	},
}

func init() {
	rootCmd.AddCommand(runCmd)

	runCmd.Flags().Bool("engine_start", false, "Start The Program.")
	runCmd.Flags().Bool("web_start", false, "Start Web Application.")

	// Here you will define your flags and configuration settings.

	// Cobra supports Persistent Flags which will work for this command
	// and all subcommands, e.g.:
	// runCmd.PersistentFlags().String("foo", "", "A help for foo")

	// Cobra supports local flags which will only run when this command
	// is called directly, e.g.:
	// runCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")
}
