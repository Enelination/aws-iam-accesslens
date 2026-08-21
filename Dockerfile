FROM node:20-alpine

COPY cli/iam-accesslens.cjs /usr/local/bin/iam-accesslens

RUN chmod +x /usr/local/bin/iam-accesslens

ENTRYPOINT ["iam-accesslens"]
