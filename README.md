# sha256_signverify_for_golang

证书生成方法：

PKCS1

openssl genrsa -out private.pem 2048

openssl rsa -in private.pem -pubout -out public.pem


PKCS1 TO PKCS8

openssl pkcs8 -topk8 -inform PEM -in private.pem -outform PEM -nocrypt -out pkcs8.pem


PKCS8 TO PKCS1

openssl pkcs8 -in pkcs8.pem -nocrypt -out pri_key.pem
