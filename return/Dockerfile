FROM ubuntu:22.04

RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      libglib2.0-0 libpcre3 libgcc-s1 socat \
 && rm -rf /var/lib/apt/lists/*

# The flag is whatever flag.txt holds at build time. Root-only: the broker runs
# as root and can read it, the sandboxee drops to nobody before it touches any
# player input and cannot.
COPY bin/broker bin/sandboxee /opt/ctf/
COPY flag.txt /flag.txt
RUN chmod 0755 /opt/ctf/broker /opt/ctf/sandboxee \
 && chown root:root /flag.txt && chmod 0400 /flag.txt

# socat forks a broker + sandboxee pair per connection, handing the socket down
# as stdin/stdout, so every player gets their own processes and their own heap.
ENV CTF_STDIO=1
EXPOSE 8888
CMD ["socat", "-T60", "TCP-LISTEN:8888,reuseaddr,fork", "EXEC:/opt/ctf/broker"]
