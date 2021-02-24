Clone this repo.
`git clone https://github.com/jrecchia1029/WAN-Core-Deployment.git`

Navigate to the `WAN-Core-Deployment` directory
`cd WAN-Core-Deployment`

Build the Dockerfile
`docker build --tag deploy-wc:latest .`

Run the container and expose the 8080 port on the docker container and mount the Deploy-Script volume
`docker run -dit -v $(pwd)/Deploy-Script:/Deploy-Script --publish 80:8081 --name deploy-wc deploy-wc:latest`

In a web browser, navigate to the host address.
`http://<host-ip>`
