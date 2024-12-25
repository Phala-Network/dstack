FROM gramineproject/gramine:v1.5

# Prevent timezone prompt by setting noninteractive frontend and configuring tzdata
ENV DEBIAN_FRONTEND=noninteractive \
    TZ=Etc/UTC \
    TZDATA=Etc/UTC \
    LC_ALL=en_US.UTF-8 \
    LANG=en_US.UTF-8

# Set timezone
RUN ln -snf /usr/share/zoneinfo/$TZ /etc/localtime && echo $TZ > /etc/timezone

# Install required packages
RUN apt update && apt install -y \
    build-essential \
    chrpath \
    diffstat \
    lz4 \
    python3 \
    locales \
    git \
    file \
    gawk \
    wget \
    curl \
    libclang-dev \
    rsyslog \
    xorriso

# Runtime dependencies
RUN apt-get update && \
    DEBIAN_FRONTEND=noninteractive apt-get install -y \
    sgx-aesm-service \
    libsgx-aesm-launch-plugin \
    libsgx-aesm-quote-ex-plugin \
    libsgx-aesm-ecdsa-plugin \
    libsgx-dcap-quote-verify \
    libsgx-dcap-default-qpl \
    psmisc

# Install Rust
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
ENV PATH="/root/.cargo/bin:${PATH}"

RUN git clone -b patches https://github.com/kvinwang/gramine-sealing-key-provider

WORKDIR /gramine-sealing-key-provider
# Build gramine-sealing-key-provider binary
RUN make target/release/gramine-sealing-key-provider
# Generate private key
RUN gramine-sgx-gen-private-key
# Build gramine manifest
RUN make RUST_LOG=info

COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh
ENTRYPOINT ["/entrypoint.sh"]
