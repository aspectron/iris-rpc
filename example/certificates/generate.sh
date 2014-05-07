#!bin/bash

openssl genrsa -des3 -out example.key 1024
openssl req -new -key example.key -out example.csr
cp example.key example.key.org
openssl rsa -in example.key.org -out example.key
openssl x509 -req -days 999999 -in example.csr -signkey example.key -out example.crt
