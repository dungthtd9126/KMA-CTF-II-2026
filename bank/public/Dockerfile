FROM ubuntu:24.04@sha256:4f1db91d9560cf107b5832c0761364ec64f46777aa4ec637cca3008f287c975e

RUN apt update && apt install -y socat && rm -rf /var/lib/apt/lists/*

RUN /usr/sbin/useradd --no-create-home -u 1001 user

COPY flag /
COPY bank /home/user/bank

RUN chmod 444 /flag && chmod 555 /home/user/bank

CMD ["socat", "TCP-LISTEN:7331,reuseaddr,fork", "EXEC:\"/home/user/bank\",su=user"]
