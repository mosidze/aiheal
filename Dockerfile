FROM golang:alpine

# Create a new user and group
RUN addgroup -S appgroup && adduser -S appuser -G appgroup

# Set the working directory to /app
WORKDIR /app

# Copy the current directory contents into the container at /app
COPY . /app

# Set the user to appuser
USER appuser

# Install the required packages
RUN go install github.com/coolbet/login/cmd/login

# Expose port 8080 to the host, so we can access it from the outside
EXPOSE 8080

# Run the command to start the development server when the container launches
ENTRYPOINT ["login"]