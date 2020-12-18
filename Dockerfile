# Use the official image as a parent image.
FROM ubuntu:latest

# Set the working directory.
WORKDIR /Deploy-Script

# Copy the file from your host to your current location.
COPY Deploy-Script .

# Add metadata to the image to describe which port the container is listening on at runtime.
EXPOSE 8080

# Run the command inside your image filesystem.
RUN apt update
RUN apt install software-properties-common -y
RUN add-apt-repository ppa:deadsnakes/ppa
RUN apt-get update && apt-get install -y \
  python3.8 \
  python3-pip
RUN ln -s /usr/bin/python3.8 /usr/bin/python
RUN ln -s /usr/bin/pip3 /usr/bin/pip

# Run the specified command within the container.
RUN pip install -r requirements.txt
CMD ["./main.py"]