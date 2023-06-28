FROM node:18-alpine

WORKDIR /app

COPY dist/ /app/
COPY package.json /app/
COPY yarn.lock /app/

RUN yarn install --prod --frozen-lockfile

ENTRYPOINT ["node", "dist/main.js"]

EXPOSE 5000
