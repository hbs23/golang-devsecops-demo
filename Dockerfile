# ---------- Build stage ----------
FROM golang:1.24-alpine AS build
WORKDIR /app
RUN apk add --no-cache git ca-certificates
COPY go.mod go.sum* ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -o app

# ---------- Runtime stage ----------
FROM alpine:3.20
WORKDIR /app
RUN apk add --no-cache ca-certificates bash curl
COPY --from=build /app/app /app/app
EXPOSE 8080
CMD ["/app/app"]
