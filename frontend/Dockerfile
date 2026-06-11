FROM node:18-alpine AS build

WORKDIR /app

ARG VUE_APP_API_BASE_URL=http://localhost:8081/api
ENV VUE_APP_API_BASE_URL=${VUE_APP_API_BASE_URL}

COPY package*.json ./
RUN npm install

COPY . .
RUN npm run build

FROM nginx:1.27-alpine

COPY nginx/default.conf /etc/nginx/conf.d/default.conf
COPY --from=build /app/dist /usr/share/nginx/html

EXPOSE 80
CMD ["nginx", "-g", "daemon off;"]
