# 2shell-tracker — feeds the 2shell.lol arrivals board (github.com/<you>/2shell.lol).
# Pure-stdlib Python so cold rebuilds stay offline (offline-resilience rules):
# no pip install, no wheels, no internet at build time. Canonical copy of this
# file + track.py lives in the 2shell.lol repo, tracker/ — build from there:
#
#   docker build -t <registry>/2shell-tracker:latest <2shell.lol>/tracker/
#   docker push  <registry>/2shell-tracker:latest
FROM python:3.12-slim

RUN useradd --uid 1000 --create-home --shell /usr/sbin/nologin tracker

COPY track.py /app/track.py

USER 1000
WORKDIR /app

ENTRYPOINT ["python3", "/app/track.py"]
