FROM golang:1.21.5-alpine3.17 AS build

RUN apk --no-cache add gcc libc-dev libpcap-dev

ADD . /go/src/github.com/rkojedzinszky/go-dhcplogger

RUN cd /go/src/github.com/rkojedzinszky/go-dhcplogger && go build . && \
    strip -s go-dhcplogger

FROM alpine:3.21

LABEL org.opencontainers.image.authors "Richard Kojedzinszky <richard@kojedz.in>"
LABEL org.opencontainers.image.source https://github.com/rkojedzinszky/go-dhcplogger

COPY --from=build /go/src/github.com/rkojedzinszky/go-dhcplogger/go-dhcplogger /

RUN apk --no-cache add libpcap libcap && \
    setcap cap_net_raw+ep /go-dhcplogger && \
    apk del libcap

USER 65534

ENTRYPOINT ["/go-dhcplogger"]
