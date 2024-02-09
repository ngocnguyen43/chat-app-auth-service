FROM node:18 as builder

# Set the working directory in the builder stage
RUN mkdir -p /usr/src
WORKDIR /usr/src

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
RUN mkdir -p /usr/src
# Install Doppler CLI
RUN wget -q -t3 'https://packages.doppler.com/public/cli/rsa.8004D9FF50437357.key' -O /etc/apk/keys/cli@doppler-8004D9FF50437357.rsa.pub && \
    echo 'https://packages.doppler.com/public/cli/alpine/any-version/main' | tee -a /etc/apk/repositories && \
    apk add doppler

WORKDIR /usr/src
ENV NODE_ENV production

ARG DOPPLER_TOKEN

ENV DOPPLER_TOKEN ${DOPPLER_TOKEN}
ENV NODE_ENV production
ENV TZ Asia/Ho_Chi_Minh
# Copy only the necessary artifacts from the builder stage
COPY --from=builder /usr/src/dist ./dist
COPY --from=builder /usr/src/prisma ./prisma
COPY --from=builder /usr/src/node_modules ./node_modules
COPY --from=builder /usr/src/package.json ./package.json

# Install only production dependencies
# RUN npm ci --production

# Expose the port
EXPOSE 6001

# Define the command to start the application
CMD [ "doppler","run","--","node", "./dist/bootstrap.js" ]