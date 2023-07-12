package database

import (
	"context"
	"fmt"
	"iatp/common/logger"
	"log"
	"strings"

	"github.com/Shopify/sarama"
	"github.com/sirupsen/logrus"
)

type Kafka struct {
	Brokers  string
	Topics   string
	Version  string // kafka 版本号
	Group    string
	Assignor string
	Oldest   bool
}

type consumer struct {
	Ready    chan bool
	CallBack func(engine string, msg []byte)
	Engine   string
}

type KafkaConsumer struct {
	Kafka    Kafka
	Consumer consumer
}

func NewKafkaConsumerObj(brokers, topics, version, group, assignor string, runDetect func(engine string, msg []byte), engine string) *KafkaConsumer {
	return &KafkaConsumer{
		Kafka: Kafka{
			Brokers:  brokers,
			Topics:   topics,
			Version:  version,
			Group:    group,
			Assignor: assignor,
			Oldest:   false,
		},
		Consumer: consumer{
			Ready:    make(chan bool),
			CallBack: runDetect,
			Engine:   engine,
		},
	}
}

func NewKafkaObj(brokers, topics, version, group, assignor string) *Kafka {
	return &Kafka{
		Brokers:  brokers,
		Topics:   topics,
		Version:  version,
		Group:    group,
		Assignor: assignor,
		Oldest:   false,
	}
}

func (kc *KafkaConsumer) KafkaConsumer(ctx context.Context) error {
	version, err := sarama.ParseKafkaVersion(kc.Kafka.Version)

	if err != nil {
		return fmt.Errorf("Error parsing Kafka version: %v", err)
	}

	/**
	 * Construct a new Sarama configuration.
	 * The Kafka cluster version has to be defined before the consumer/producer is initialized.
	 */
	config := sarama.NewConfig()
	config.Version = version

	switch kc.Kafka.Assignor {
	case "sticky":
		config.Consumer.Group.Rebalance.Strategy = sarama.BalanceStrategySticky
	case "roundrobin":
		config.Consumer.Group.Rebalance.Strategy = sarama.BalanceStrategyRoundRobin
	case "range":
		config.Consumer.Group.Rebalance.Strategy = sarama.BalanceStrategyRange
	default:
		return fmt.Errorf("Unrecognized consumer group partition assignor: %s", kc.Kafka.Assignor)
	}

	config.Consumer.Offsets.Initial = sarama.OffsetNewest

	/**
	 * Setup a new Sarama consumer group
	 */
	client, err := sarama.NewConsumerGroup(strings.Split(kc.Kafka.Brokers, ","), kc.Kafka.Group, config)
	if err != nil {
		return fmt.Errorf("Error creating consumer group client: %v", err)
	}

	go func() {
		for {
			// `Consume` should be called inside an infinite loop, when a
			// server-side rebalance happens, the consumer session will need to be
			// recreated to get the new claims
			if err := client.Consume(ctx, strings.Split(kc.Kafka.Topics, ","), &kc.Consumer); err != nil {
				// TODO: 错误需要记录到日志文件
				logger.IatpLogger.WithFields(
					logrus.Fields{
						"error":   err,
						"broker":  kc.Kafka.Brokers,
						"topic":   kc.Kafka.Topics,
						"version": kc.Kafka.Version,
					},
				).Errorln("Error from consumer")
				return
			}
			// check if context was cancelled, signaling that the consumer should stop
			if ctx.Err() != nil {
				return
			}
			kc.Consumer.Ready = make(chan bool)
		}
	}()

	<-kc.Consumer.Ready // Await till the consumer has been set up
	log.Println("Sarama consumer up and running!...")

	for {
		select {
		case <-ctx.Done():
			logger.IatpLogger.WithFields(
				logrus.Fields{
					"broker":  kc.Kafka.Brokers,
					"topic":   kc.Kafka.Topics,
					"version": kc.Kafka.Version,
				},
			).Infoln("关闭Kafka消费")
			if err = client.Close(); err != nil {
				return fmt.Errorf("Error closing client: %v", err)
			}
			return nil
		default:
			continue
		}
	}
}

// Setup is run at the beginning of a new session, before ConsumeClaim
func (c *consumer) Setup(sarama.ConsumerGroupSession) error {
	// Mark the consumer as ready
	close(c.Ready)
	return nil
}

// Cleanup is run at the end of a session, once all ConsumeClaim goroutines have exited
func (c *consumer) Cleanup(sarama.ConsumerGroupSession) error {
	return nil
}

// ConsumeClaim must start a consumer loop of ConsumerGroupClaim's Messages().
func (c *consumer) ConsumeClaim(session sarama.ConsumerGroupSession, claim sarama.ConsumerGroupClaim) error {

	// NOTE:
	// Do not move the code below to a goroutine.
	// The `ConsumeClaim` itself is called within a goroutine, see:
	// https://github.com/Shopify/sarama/blob/master/consumer_group.go#L27-L29
	for message := range claim.Messages() {
		// 调用回调
		go c.CallBack(c.Engine, message.Value)
		session.MarkMessage(message, "")
	}
	return nil
}
