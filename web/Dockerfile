FROM node:20-alpine
# node:20-alpine tidak membawa zoneinfo: tanpa tzdata, TZ=Asia/Jakarta diam-diam
# diabaikan dan Node tetap UTC — jam tampil dan bucket grafik jadi geser 7 jam.
RUN apk add --no-cache tzdata
WORKDIR /app
COPY package*.json ./
RUN npm install
COPY . .
EXPOSE 880
CMD ["npm", "start"]
