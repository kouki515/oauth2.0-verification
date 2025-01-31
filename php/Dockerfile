FROM php:8.1.7-fpm

RUN apt-get update \
&& apt-get install -y \
git \
zip \
unzip \
vim

RUN apt-get update \
    && apt-get install -y libpq-dev \
    && docker-php-ext-install pdo_mysql

COPY php.ini /usr/local/etc/php/

WORKDIR /var/code

COPY --from=composer:latest /usr/bin/composer /usr/bin/composer

RUN composer require guzzlehttp/guzzle
