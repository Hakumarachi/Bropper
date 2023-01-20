FROM gcc

MAINTAINER Aku

COPY chall_fork.c /chall_fork.c
COPY serve.c /serve.c
COPY serve.h /serve.h

RUN gcc -fpie -fstack-protector /serve.c /chall_fork.c -o server

ENTRYPOINT ["/server"]
