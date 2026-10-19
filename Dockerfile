# fakepve as a container: a fake Proxmox VE API on port 8006.
#
#   docker build -t fakepve .
#   docker run --rm -p 127.0.0.1:8006:8006 fakepve
#
# Publish the port on loopback only (127.0.0.1: above): the login is root@pam / secret
# unless PVE_PASS is set (docker run -e PVE_PASS=... fakepve), and it is public.
# The default command serves examples/guests.json on all interfaces with
# time_scale 0 (tasks finish before the request returns). Pass your own
# arguments after the image name to change that, for example
#   docker run -p 127.0.0.1:8006:8006 fakepve guests.json --host 0.0.0.0 --time-scale 0.01
# or build an image FROM this one that adds your own guests file.
FROM python:3.12-slim

WORKDIR /opt/fakepve
COPY pyproject.toml README.md LICENSE ./
COPY src ./src
COPY examples/guests.json ./guests.json
RUN pip install --no-cache-dir '.[crypto]'

EXPOSE 8006
USER nobody
HEALTHCHECK --interval=5s --timeout=3s --start-period=3s --retries=10 \
    CMD ["python", "-c", "import socket; socket.create_connection(('127.0.0.1', 8006), 2)"]
ENTRYPOINT ["python", "-m", "fakepve"]
CMD ["guests.json", "--host", "0.0.0.0", "--time-scale", "0"]
