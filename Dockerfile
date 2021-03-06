# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

FROM golang:latest AS buildStage

WORKDIR /opt
COPY . .
# This is necessary to statically compile all
# C libraries into the executable. Otherwise
# the Alpine installation will fail out with
# a "no such directory" when attempting to execute
# the binary (it can't find the shared libs).
ENV CGO_ENABLED=0
RUN apt-get update
RUN apt-get install -y libnss3-tools
RUN go test ./lib/... && go build capi.go

FROM alpine:latest

RUN apk add nss-tools bash
COPY --from=buildStage /opt/ /opt/

CMD ["/opt/capi"]