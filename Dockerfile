# Use Arch Linux as the base image
FROM archlinux:latest

# Install dependencies: Python, MinGW-w64, Make, and other required tools
RUN pacman -Syu --noconfirm && \
    pacman -Sy --noconfirm \
        mingw-w64-gcc \
        make \
        python \
        python-pip \
        base-devel \
        git \
        nasm

# Set the working directory where the build will happen
WORKDIR /alcatrazLdr

# Copy the entire project into the container
COPY . .

CMD ["make", "clean", "all"]
