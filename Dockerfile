FROM node:20-alpine

# Install dependencies for bcrypt native builds
RUN apk add --no-cache python3 make g++

WORKDIR /app

# Copy package files and install dependencies
COPY package*.json ./
RUN npm ci --omit=dev

# Copy source
COPY . .

# Remove dev/local-only files
RUN rm -f .env .env.*

EXPOSE 3000

CMD ["node", "server.js"]
