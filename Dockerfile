# Common arguments for images
ARG CHALLENGE_BINARY="unshellable"
ARG TORTH_COMPILER="torth"

### Builder image for compiling challenge binaries ###

FROM alpine:3 AS builder
SHELL ["/bin/sh", "-c"]

# Install required programs
RUN apk update
RUN apk add --update --no-cache \
    binutils \
    nasm \
    wget

ARG CHALLENGE_SOURCE_FILE="unshellable.torth"
ARG CHALLENGE_BINARY # Defined earlier
ARG TORTH_COMPILER # Defined earlier

# Compile CFT challenge binary
WORKDIR /tmp
COPY $CHALLENGE_SOURCE_FILE .
RUN wget https://github.com/frendsick/torth/releases/download/v1.0.0/$TORTH_COMPILER && chmod +x $TORTH_COMPILER
RUN wget https://github.com/frendsick/torth/releases/download/v1.0.0/std.torth
RUN ./$TORTH_COMPILER $CHALLENGE_SOURCE_FILE --out $CHALLENGE_BINARY

### Production image ###

FROM alpine:3

# Install required programs
RUN apk update
RUN apk add --update --no-cache \
    bash \
    openssh-server \
    shadow

# Disable shell history
RUN echo "set +o history" >> /etc/profile

# Clear message of the day (motd)
RUN > /etc/motd

# Configure SSHD
RUN echo "PasswordAuthentication yes" >> /etc/ssh/sshd_config

# Add user for SSH
ARG SSH_USERNAME=shelldon
RUN adduser -D -s /bin/bash $SSH_USERNAME
RUN --mount=type=secret,id=ssh_password echo "$SSH_USERNAME:`cat /run/secrets/ssh_password`" | chpasswd

# Prevent SSH user from changing its password
RUN chage --mindays 1337 $SSH_USERNAME

# Copy compiled binaries from the builder
ARG CHALLENGE_BINARY # Defined earlier
ARG TORTH_COMPILER # Defined earlier
COPY --from=builder --chown=root --chmod=4755 /tmp/$CHALLENGE_BINARY /home/$SSH_USERNAME

# Set up flag file
RUN --mount=type=secret,id=ctf_flag cp /run/secrets/ctf_flag "/root/flag.txt"

# Define entrypoint
ENV ENTRYPOINT=entrypoint.sh
COPY --chmod=700 $ENTRYPOINT /
ENTRYPOINT ./$ENTRYPOINT
