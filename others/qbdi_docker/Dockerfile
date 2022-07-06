# Set the base image
FROM qbdi/qbdi:x86_ubuntu

# Set the environment variables
ENV USER="docker" \
    HOME="/home/docker"

# Install the packages
RUN apt-get update && \
    apt-get upgrade -y && \
    apt-get install -y \
        build-essential \
        cmake \
        libstdc++-8-dev \
        python \
        python-dev \
        python3 \
        python3-dev \
        sudo \
        bash && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Add and switch to a new user
RUN adduser --disabled-password --gecos '' $USER && \
    adduser $USER sudo && \
    echo '%sudo ALL=(ALL) NOPASSWD:ALL' >> /etc/sudoers
USER $USER

# Set the working directory
WORKDIR $HOME

# Create the QBDI build environment
RUN qbdi-preload-template-X86
COPY qbdi_preload_template.c .
COPY dictionaries/ .
RUN mkdir traces
RUN cmake . && make

# Command to run on startup
CMD ["/bin/bash"]