FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends socat \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --create-home --uid 1000 --shell /usr/sbin/nologin ctf

WORKDIR /app
COPY mail_service libmailio.so libmailstr.so libmailmem.so /app/
COPY flag.txt /flag.txt

RUN test -s /flag.txt \
    && chown root:ctf /flag.txt \
    && chmod 440 /flag.txt \
    && chown -R root:root /app \
    && chmod 755 /app /app/mail_service /app/libmailio.so /app/libmailstr.so /app/libmailmem.so

USER ctf
EXPOSE 1337
CMD ["socat", "TCP-LISTEN:1337,reuseaddr,fork", "EXEC:/app/mail_service,stderr"]
