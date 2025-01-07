# Use an official Alpine Linux image as the base
FROM alpine:latest

# Set environment variable to prevent interactive prompts
ENV PYTHONUNBUFFERED=1

# Update the package repository and install necessary packages
RUN apk update && \
    apk add --no-cache python3 py3-pip figlet git && \
    rm -rf /var/cache/apk/*

# Create a virtual environment
RUN python3 -m venv /opt/venv

# Activate the virtual environment and install Python packages
RUN /opt/venv/bin/pip install --no-cache-dir scapy getmac

# Download the code from GitHub
RUN git clone https://github.com/imroot056/my-net-mon.git

# Copy the application file to the container
RUN cp my-net-mon/python-file/my-net-mon.py /opt/

# Create a directory for your application
WORKDIR /opt/

# Creating directory to store logs
RUN mkdir logfiles

# Set entrypoint to activate the virtual environment and run the application
ENTRYPOINT ["/opt/venv/bin/python3", "my-net-mon.py"]

CMD ["-w"]
