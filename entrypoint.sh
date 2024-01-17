#!/bin/bash

source .env
sleep 30
./iatp init --mongourl mongodb://$MONGOUSER:$MONGOPWD@127.0.0.1:27017
./iatp init --mongourl mongodb://$MONGOUSER:$MONGOPWD@127.0.0.1:27017 --domainname $DCNAME --domainserver $DCSERVER --username $DCUSER --password $DCPWD --ssl
./iatp init --mongourl mongodb://$MONGOUSER:$MONGOPWD@127.0.0.1:27017 --index
./iatp  web --init --authdomain $DCNAME --user $WEBUSER
./iatp  source --sourcename ITEvent --sourceengine event_log --brokers $BROKER --topic winlogbeat --group iatp --oldest false --kafka true
nohup ./iatp run --engine_start > engine.log 2>&1 &
nohup ./iatp run --web_start > web.log 2>&1 &
# 使用tail命令持续输出日志
tail -f engine.log web.log