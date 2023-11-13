# FROM node:18-alpine3.15
# # Create app directory
# WORKDIR /usr/src/app
# # Install app dependencies
# # A wildcard is used to ensure both package.json AND package-lock.json are copied
# # where available (npm@5+)
# COPY package*.json ./
# COPY prisma ./prisma/

# COPY . .
# RUN npm install \
#     && npm run build \
#     && rm -rf node_modules \
#     && npm install --production

# # If you are building your code for production
# # RUN npm ci --omit=dev
# EXPOSE 4000
# CMD [ "npm","run","start:prod" ]
# Stage 1: Build the application
FROM node:18 as builder

# Set the working directory in the builder stage
WORKDIR /usr/src/app

# Copy the package.json and package-lock.json to the working directory
COPY package*.json ./
COPY prisma ./prisma/
COPY . .
# Install app dependencies and build the application

# RUN npm audit fix --force --production 
RUN npm ci --verbose --force \
    && npm run build

# Stage 2: Create the final image
FROM node:18-alpine3.15

# Set the working directory in the final stage
WORKDIR /usr/src/app

# Copy only the necessary artifacts from the builder stage
COPY --from=builder /usr/src/app/dist ./dist
COPY --from=builder /usr/src/app/prisma ./prisma
COPY --from=builder /usr/src/app/node_modules ./node_modules
COPY --from=builder /usr/src/app/package.json ./package.json

# Install only production dependencies
# RUN npm ci --production

# Expose the port
EXPOSE 4000

# Define the command to start the application
CMD [ "npm", "run", "start:prod" ]