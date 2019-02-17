############################
# STEP 1 build executable binary
############################
FROM golang:latest AS buildStage

WORKDIR /opt
COPY . .
#ENV GOOS=linux
#ENV GOARCH=amd64
# This is necessary to statically compile all
# C libraries into the executable. Otherwise
# the Alpine installation will fail out with
# a "no such directory" when attempting to execute
# the binary (it can't find the shared libs).
ENV CGO_ENABLED=0
RUN apt-get update
RUN apt-get install -y libnss3-tools
RUN go test ./... && go build capi.go

############################
# STEP 2 build a small image
############################
FROM alpine:latest

RUN apk add nss-tools bash
COPY --from=buildStage /opt/ /opt/

CMD ["/opt/capi"]