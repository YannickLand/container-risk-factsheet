FROM node:18-alpine

# Set working directory
WORKDIR /app

# Copy package files
COPY package*.json ./

# Create non-root user, install dependencies and tools, copy source, and set permissions
RUN addgroup -g 1001 -S nodejs && \
    adduser -S analyzeruser -u 1001 && \
    npm ci --only=production && \
    apk add --no-cache --update \
        curl=8.2.1-r0 \
        wget=1.21.4-r0 \
        vim=9.0.1568-r0

# Copy source code
COPY . .

# Change ownership to non-root user
RUN chown -R analyzeruser:nodejs /app

# Expose port
EXPOSE 3000

# Switch to non-root user
USER analyzeruser

# Use exec form for CMD
CMD ["npm", "start"]
