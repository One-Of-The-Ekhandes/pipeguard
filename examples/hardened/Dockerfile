FROM node:22.11-slim
WORKDIR /app
COPY --chown=node:node . .
RUN npm ci --omit=dev
USER node
EXPOSE 3000
HEALTHCHECK CMD node healthcheck.js
CMD ["node", "server.js"]
