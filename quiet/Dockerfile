FROM ubuntu:22.04

RUN apt-get update \
    && apt-get install -y --no-install-recommends socat \
    && rm -rf /var/lib/apt/lists/*

RUN useradd -m ctf
WORKDIR /home/ctf

COPY chall ./chall
COPY ld-2.35.so ./ld-2.35.so
COPY libc-2.35.so ./libc.so.6
COPY rules ./rules

ARG FLAG="FLAG{quiet_ledger_sample_flag}"
RUN printf '%s\n' "$FLAG" > ./flag.txt \
    && chown -R root:root /home/ctf \
    && chmod 755 /home/ctf /home/ctf/chall /home/ctf/ld-2.35.so \
    && chmod 644 /home/ctf/libc.so.6 /home/ctf/flag.txt /home/ctf/rules/*.pkg

USER ctf
EXPOSE 31337
CMD ["socat", "TCP-LISTEN:31337,reuseaddr,fork", "EXEC:/home/ctf/ld-2.35.so --library-path /home/ctf /home/ctf/chall,stderr"]
