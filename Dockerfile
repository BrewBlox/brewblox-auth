FROM node:18-alpine

WORKDIR /opt/app

COPY build/* /opt/app/

ENTRYPOINT ["node", "index.js"]

EXPOSE 3000
EXPOSE 3001
