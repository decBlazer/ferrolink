# ---------- build stage ----------
    FROM node:22-alpine AS build
    WORKDIR /src
    COPY . .
    RUN npm ci && npm run build          # outputs to dist/
    
    # ---------- runtime stage ----------
    FROM nginx:stable-alpine
    COPY --from=build /src/dist /usr/share/nginx/htmls