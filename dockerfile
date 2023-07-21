FROM node:18-alpine3.15
# Create app directory
WORKDIR /usr/src/app
# Install app dependencies
# A wildcard is used to ensure both package.json AND package-lock.json are copied
# where available (npm@5+)
COPY package*.json ./
COPY prisma ./prisma/

COPY . .
RUN npm install \
    && npm run build \
    && rm -rf node_modules \
    && npm install --production

# If you are building your code for production
# RUN npm ci --omit=dev
EXPOSE 4000
CMD [ "npm","run","start:prod" ]
