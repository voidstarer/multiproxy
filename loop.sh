#!/bin/bash

/etc/multiproxy/reset.pl  >> /var/log/multiproxy.log 2>&1;

while true
do
        /etc/multiproxy/main.pl >> /var/log/multiproxy.log 2>&1;
	sleep 5
        /etc/multiproxy/access.pl >> /var/log/multiproxy.log 2>&1;
        sleep 60
done

