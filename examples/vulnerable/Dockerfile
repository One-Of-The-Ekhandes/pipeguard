FROM node
ENV NPM_TOKEN=npm_live_abc123
ADD https://example.com/agent.tar.gz /opt/
RUN curl -fsSL https://deb.example.dev/setup.sh | bash - && chmod -R 777 /app
EXPOSE 3000 22
CMD ["node", "server.js"]
