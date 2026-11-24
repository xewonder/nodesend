FROM node:20-alpine

WORKDIR /app

COPY package*.json ./

RUN npm install --omit=dev

COPY bridge.js ./
# Clubs is a directory of small modules that bridge.js requires. Without this line the image builds
# and then dies at startup on `Cannot find module './clubs'`, so the copy is part of the feature,
# not an optimisation. Nothing else about the build or the startup command changes.
COPY clubs/ ./clubs/
# The same rule applies to the player gateway, and the same failure mode would: `bridge.js` requires
# ./ncb/gateway at boot, so an image without this line starts, is healthy in Coolify's eyes for the
# length of a container restart, and then crash-loops on `Cannot find module`. Adding a directory to
# a Node image is not a runtime change — nothing in the gateway is consulted unless bridge.js loads it.
COPY ncb/ ./ncb/
# Tournaments follows the identical rule and would have the identical failure mode without it:
# bridge.js requires ./tournaments at boot, so an image missing this directory builds green, answers a
# health check for the length of a container restart, and then crash-loops on `Cannot find module`.
COPY tournaments/ ./tournaments/
# Games follows the identical rule and would fail the identical way without it: bridge.js requires
# ./games at boot, so an image missing this directory builds green, answers a health check for the length
# of a container restart, and then crash-loops on `Cannot find module`.
COPY games/ ./games/

ENV PORT=3001

EXPOSE 3001

CMD ["npm", "start"]
