FROM ubuntu:16.04
MAINTAINER Sai Vegasena

RUN apt-get update && apt-get install -y \
    apt-utils \
    build-essential \
    vim \
    clang-3.9 \
    clang++-3.9 \
    git

ADD . /home/Insanity

WORKDIR /home/Insanity

CMD ["/bin/bash"]
