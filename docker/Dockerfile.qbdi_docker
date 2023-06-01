FROM qbdi/qbdi:x86_ubuntu

ENV USER="docker" \
    HOME="/home/docker"

RUN apt-get update \
                   && apt-get upgrade -y \
                       && apt-get install -y \
        build-essential \
        cmake \
        libstdc++-8-dev \
        python \
        python-dev \
        python3 \
        python3-dev \
        sudo \
        bash \
             && apt-get clean \
                  && rm -rf /var/lib/apt/lists/*

RUN adduser --disabled-password --gecos '' $USER \
                                                 && adduser $USER sudo \
                       && echo '%sudo ALL=(ALL) NOPASSWD:ALL' >> /etc/sudoers
USER $USER

WORKDIR $HOME

RUN qbdi-preload-template-X86
RUN mkdir results

COPY qbdi_preload_template.c .
COPY utarray.h .

RUN cmake . && make

CMD ["/bin/bash"]
