FROM gcc

MAINTAINER Aku

COPY chall.c /chall.c
COPY server.sh /server.sh

RUN gcc -no-pie -fno-stack-protector /chall.c -o chall

ENTRYPOINT ["/server.sh"]
