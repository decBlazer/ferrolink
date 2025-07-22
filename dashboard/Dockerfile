FROM node:20-alpine AS builder
WORKDIR /app
# copy manifest(s)
COPY package*.json ./
# install deps (ci if lockfile exists)
RUN if [ -f package-lock.json ]; then npm ci --silent; else npm install --silent; fi
COPY . .
RUN npm run build

FROM nginx:alpine
COPY --from=builder /app/dist /usr/share/nginx/html
EXPOSE 80
CMD ["nginx", "-g", "daemon off;"] 