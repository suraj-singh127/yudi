# 1️⃣ Use Node.js as the base image
FROM node:18

# 2️⃣ Set the working directory inside the container
WORKDIR /app

# 3️⃣ Copy package.json and install dependencies
COPY package.json package-lock.json ./
RUN npm install

# 4️⃣ Copy the entire frontend source code
COPY . .

# 5️⃣ Expose Vite's development server port (5173)
EXPOSE 5173

# 6️⃣ Start the Vite development server
CMD ["npm", "run", "dev", "--", "--host"]
