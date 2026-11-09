# 2shell-tracker — feeds the 2shell.lol arrivals board.
# Pure-stdlib Python so cold rebuilds stay dependency-free: no pip install,
# no wheels, no internet at build time.
#
#   docker build -t 2shell-tracker:latest <2shell.lol>/tracker/
# A private mirror can override the base image at build time:
#   docker build --build-arg BASE_IMAGE=python:3.12-slim -t <registry>/2shell-tracker:latest <2shell.lol>/tracker/
ARG BASE_IMAGE=python:3.12-slim
FROM ${BASE_IMAGE}

RUN useradd --uid 1000 --create-home --shell /usr/sbin/nologin tracker

COPY track.py /app/track.py

USER 1000
WORKDIR /app

ENTRYPOINT ["python3", "/app/track.py"]
