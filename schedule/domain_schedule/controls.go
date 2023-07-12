package domain_schedule

import (
	"context"
	"iatp/common/domain"
	"iatp/setting"

	"go.mongodb.org/mongo-driver/bson"
)

type Control struct{}

func NewControl() *Control {
	return &Control{}
}

func (c *Control) Run() {
	// 定义注册时间
	cursor := setting.DomainMongo.FindAll(bson.M{})

	var d domain.Domain

	for cursor.Next(context.TODO()) {
		// 获取所有域控主机列表
		cursor.Decode(&d)
		// 获取所有域控主机列表
		controls := d.GetDomainControls()
		d.DomainControls = controls
		setting.DomainMongo.UpdateOne(bson.M{"domainname": d.DomainName}, bson.D{
			{"$set", d},
		})
	}
}
