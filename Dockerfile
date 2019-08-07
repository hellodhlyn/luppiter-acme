FROM node:10-slim

WORKDIR /usr/src/app

COPY package.json package.json
COPY yarn.lock yarn.lock

RUN npm install -g yarn
RUN yarn

COPY . .

CMD ["yarn", "start"]
