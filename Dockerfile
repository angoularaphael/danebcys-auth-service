FROM node:20-alpine

WORKDIR /app
ENV NPM_CONFIG_STRICT_SSL=false

COPY package*.json ./
RUN npm install

COPY . .

EXPOSE 3001

CMD ["npm", "run", "dev"]
