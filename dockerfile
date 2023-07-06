FROM node:18-alpine3.15
# Create app directory
WORKDIR /usr/src/app
#install dependencies
COPY . .
RUN npm install
#bundle app src
COPY . /usr/src/app
EXPOSE 3000 9204
CMD [ "npm" , "build" ]