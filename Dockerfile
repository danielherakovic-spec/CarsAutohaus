FROM node:20-alpine

WORKDIR /app
ENV NODE_ENV=production
ENV PORT=4173

COPY package.json ./
COPY index.html manifest.webmanifest icon.svg sw.js server.js ./

RUN addgroup -S autovalue && adduser -S autovalue -G autovalue && mkdir -p /app/data && chown -R autovalue:autovalue /app

USER autovalue
VOLUME ["/app/data"]
EXPOSE 4173

CMD ["node", "server.js"]
