FROM ubuntu:18.04

LABEL maintainer="Team Stingar <team-stingar@duke.edu>"
LABEL name="hpfeeds-output"
LABEL version="1.9.2"
LABEL release="1"
LABEL summary="Community Honey Network hpfeeds output library"
LABEL description="Small App for reading from hpfeeds broker and writing output to various outputs"
LABEL authoritative-source-url="https://github.com/CommunityHoneyNetwork/hpfeeds-output"
LABEL changelog-url="https://github.com/CommunityHoneyNetwork/hpfeeds-output/commits/master"

ENV playbook "hpfeeds-output.yml"
ENV DEBIAN_FRONTEND "noninteractive"

RUN apt-get update \
  && apt-get upgrade -y \
  && apt-get install --no-install-recommends -y gcc git python3-dev python3-pip libgeoip-dev \
  && apt-get clean \
  && rm -rf /var/lib/apt/lists/*

COPY hpfeeds-output /opt/hpfeeds-output
COPY entrypoint.sh /opt/entrypoint.sh

# hadolint ignore=DL3013
RUN python3 -m pip install --upgrade pip setuptools wheel \
  && python3 -m pip install -r /opt/hpfeeds-output/requirements.txt \
  && python3 -m pip install git+https://github.com/CommunityHoneyNetwork/hpfeeds3.git

ENTRYPOINT ["/opt/entrypoint.sh"]
