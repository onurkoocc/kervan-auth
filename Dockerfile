# syntax=docker/dockerfile:1
# SPEC §11: dependencies are fetched in a layer that sees only the lock file and
# runs no package scripts; the sources are compiled without network.

FROM node:22-slim AS deps
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci --ignore-scripts

FROM deps AS build
COPY tsconfig.json tsconfig.build.json ./
COPY src ./src
RUN --network=none npm run build
RUN --network=none npm prune --omit=dev --ignore-scripts

FROM node:22-slim
ENV NODE_ENV=production PORT=9000
WORKDIR /app
COPY --from=build /app/package.json ./
COPY --from=build /app/node_modules ./node_modules
COPY --from=build /app/dist ./dist
RUN mkdir -p /var/log/kervan && chown node:node /var/log/kervan
USER node
EXPOSE 9000
HEALTHCHECK --interval=10s --timeout=3s --retries=3 \
  CMD ["node", "-e", "fetch('http://127.0.0.1:'+(process.env.PORT||9000)+'/health').then(r=>process.exit(r.ok?0:1),()=>process.exit(1))"]
CMD ["node", "dist/main.js"]
