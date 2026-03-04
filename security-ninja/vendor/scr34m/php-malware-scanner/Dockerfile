FROM php:8.2-cli

# Install dependencies
RUN apt-get update && apt-get install -y \
    git \
    unzip \
    libzip-dev \
    && docker-php-ext-install zip

WORKDIR /scanner
COPY . .
RUN chmod +x scan

ENTRYPOINT ["./scan"]
CMD ["/code"] 