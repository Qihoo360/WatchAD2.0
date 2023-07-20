FROM golang:1.17.1-buster as builder
# 为我们的镜像设置必要的环境变量
ENV GO111MODULE=on \
    GOPROXY=https://goproxy.cn,direct
WORKDIR /go/src
COPY ./  /go/src/iatp_opensource
RUN cd /go/src/iatp_opensource && go mod vendor
RUN cd /go/src/iatp_opensource && go build -o /go/iatp main.go

FROM centos
WORKDIR /home
COPY ./.env ./.env
COPY ./entrypoint.sh ./entrypoint.sh
COPY ./iatp_wbm/static ./iatp_wbm/static
COPY ./iatp_wbm/templates ./iatp_wbm/templates
COPY --from=builder /go/iatp ./iatp
COPY --from=builder /go/iatp ./iatp
RUN chmod 755 ./iatp
RUN chmod 755 ./entrypoint.sh

# 执行运行
# ./iatp run --web_start1
CMD ["./entrypoint.sh"]
#CMD ["./iatp","run","--web_start"]

