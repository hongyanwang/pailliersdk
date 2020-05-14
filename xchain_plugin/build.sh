#!/bin/bash

:<<!
protoc -I pb pb/tf.proto \
       --go_out=paths=source_relative:pb
!
export GO111MODULE=on
go build -buildmode=plugin -o=libpailliersdk.so.0.1

