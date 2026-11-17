FROM node:20-alpine

WORKDIR /app

COPY package*.json ./

RUN npm install --omit=dev

COPY bridge.js ./
# Clubs is a directory of small modules that bridge.js requires. Without this line the image builds
# and then dies at startup on `Cannot find module './clubs'`, so the copy is part of the feature,
# not an optimisation. Nothing else about the build or the startup command changes.
COPY clubs/ ./clubs/

ENV PORT=3001

EXPOSE 3001

CMD ["npm", "start"]
