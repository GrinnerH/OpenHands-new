FROM alpine:3.19

# ==== 1️⃣ 设置国内镜像源（加速 APK 下载）====
RUN sed -i 's|dl-cdn.alpinelinux.org|mirrors.tuna.tsinghua.edu.cn|g' /etc/apk/repositories

# ==== 2️⃣ 安装基础依赖 ====
# Install dependencies
RUN apk update && apk upgrade && apk add --no-cache \
    git \
    curl \
    wget \
    unzip \
    python3 \
    py3-pip \
    openjdk17-jdk \
    gnupg \
    bash \
    nss \
    ncurses \
    php

# ==== 3️⃣ Python 虚拟环境 ====
# Set up a virtual environment for Python packages
RUN python3 -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

# Install huggingface_hub to download datasets in the virtual environment
# ==== 4️⃣ 设置 pip 国内源 ====
RUN pip config set global.index-url https://pypi.tuna.tsinghua.edu.cn/simple && \
    pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir huggingface_hub

# ==== 5️⃣ 下载并安装 Joern ====
# Create working directory
WORKDIR /app

# Run the Python script to download the dataset
# Use the python command from the virtual environment


RUN mkdir joern
COPY joern-install.sh /app/joern/joern-install.sh
# RUN curl -L "https://ghproxy.cn/https://github.com/joernio/joern/releases/latest/download/joern-install.sh" -o joern-install.sh
RUN cd joern \
    && chmod u+x joern-install.sh \
    # Run non-interactively (remove --interactive flag)
    && bash ./joern-install.sh --without-plugins

    # ==== 6️⃣ 设置 Joern 环境 ====
# Prepare Joern home
RUN mkdir -p /opt/joern/joern-cli
# Set the working directory to Joern directory
WORKDIR /opt/joern/joern-cli

# Expose the port that Joern will use
EXPOSE 9685
CMD ["./joern", "--server", "--server-host", "0.0.0.0", "--server-port", "9685"]
