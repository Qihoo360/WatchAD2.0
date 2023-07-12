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
	"iatp/common"

	"github.com/spf13/cobra"
)

var (
	sourcename, sourceengine, brokers, topic, group string
)

// sourceCmd represents the source command
var sourceCmd = &cobra.Command{
	Use:   "source",
	Short: "Source of Log Data",
	Long: `Source of Log Data For example:

event_log
`,
	Run: func(cmd *cobra.Command, args []string) {
		kafka, _ := cmd.Flags().GetBool("kafka")
		if kafka {
			oldest, _ := cmd.Flags().GetBool("oldest")
			registerKafkaSource(oldest)
		} else {
			fmt.Println("[-] 暂不支持非kafka数据源")
		}
	},
}

func init() {
	rootCmd.AddCommand(sourceCmd)

	sourceCmd.Flags().StringVar(&sourcename, "sourcename", "", "Source Type Name. eg: ITEvent")
	sourceCmd.Flags().StringVar(&sourceengine, "sourceengine", "", "Source Type Name. eg: event_log")
	sourceCmd.Flags().StringVar(&brokers, "brokers", "", "Kafka Brokers. eg: 10.10.10.10:9092")
	sourceCmd.Flags().StringVar(&topic, "topic", "", "Kafka Topic. eg: system_event")
	sourceCmd.Flags().StringVar(&group, "group", "", "Kafka Group. eg: sec-ata")
	sourceCmd.Flags().Bool("oldest", false, "Whether to consume previous data.")

	sourceCmd.Flags().Bool("kafka", false, "Whether to consume previous data.")
	// Here you will define your flags and configuration settings.

	// Cobra supports Persistent Flags which will work for this command
	// and all subcommands, e.g.:
	// sourceCmd.PersistentFlags().String("foo", "", "A help for foo")

	// Cobra supports local flags which will only run when this command
	// is called directly, e.g.:
	// sourceCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")
}

func registerKafkaSource(oldest bool) {
	if sourceengine == "" || brokers == "" || topic == "" || group == "" || sourcename == "" {
		fmt.Println("配置项不完整")
		return
	}

	source_config := &common.Source{
		SourceName: sourcename,
		SourceType: "kafka",
		SourceConfig: common.KafkaSourceConfig{
			Brokers:  brokers,
			Topics:   topic,
			Version:  "1.1.1",
			Group:    group,
			Assignor: "roundrobin",
			Oldest:   oldest,
		},
		SourceEngine: sourceengine,
		SourceStatus: false,
	}

	source_config.RegisterSource()
}
