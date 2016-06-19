#!/bin/bash
openssl genrsa -out tun.key 2048
openssl req -new -x509 -days 3650 -key tun.key -out tun.crt -subj "/CN=tun"
