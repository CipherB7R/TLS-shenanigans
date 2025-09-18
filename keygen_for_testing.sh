#!/bin/bash

# RSA_key_machine_role.pem
openssl genrsa -traditional -out RSA_key_client_client.pem 2048
openssl genrsa -traditional -out RSA_key_attacker_client.pem 2048
openssl genrsa -traditional -out RSA_key_attacker_server.pem 2048
openssl genrsa -traditional -out RSA_key_server_server.pem 2048


openssl req -new -key RSA_key_client_client.pem -out signreq_client_client.csr
openssl x509 -req -days 365 -in signreq_client_client.csr -signkey RSA_key_client_client.pem -out client_certificate.pem

openssl req -new -key RSA_key_attacker_server.pem -out signreq_attacker_server.csr
openssl x509 -req -days 365 -in signreq_attacker_server.csr -signkey RSA_key_attacker_server.pem -out attacker_server_certificate.pem

openssl req -new -key RSA_key_server_server.pem -out signreq_server_server.csr
openssl x509 -req -days 365 -in signreq_server_server.csr -signkey RSA_key_server_server.pem -out server_certificate.pem
