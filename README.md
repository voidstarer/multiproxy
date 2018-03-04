# multiproxy

To decrypt db_connect.txt.enc to db_connect.txt:
openssl aes-256-cbc -d -a -in db_connect.txt.enc -out db_connect.txt

To encrypt db_connect.txt to db_connect.txt.enc:
openssl aes-256-cbc -a -salt -in db_connect.txt -out db_connect.txt.enc

Copy multiproxy.bin to /usr/bin/multiproxy
