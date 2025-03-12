# Use Node.js as the base image
FROM node:20

# Set the working directory inside the container
WORKDIR /app

# Copy package.json and package-lock.json first
COPY package.json package-lock.json /app/

# Install dependencies
RUN npm install

# Copy the rest of the application files
COPY . /app

# Expose the frontend development port
EXPOSE 5173

# Start the frontend application
CMD ["npm", "run", "dev", "--", "--host"]
