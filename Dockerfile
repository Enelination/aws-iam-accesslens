FROM node:20-alpine

RUN addgroup -S appgroup && adduser -S appuser -G appgroup

COPY cli/iam-accesslens.cjs /usr/local/bin/iam-accesslens

RUN chmod +x /usr/local/bin/iam-accesslens

USER appuser

ENTRYPOINT ["iam-accesslens"]
