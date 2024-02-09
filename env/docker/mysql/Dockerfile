FROM mysql:latest

ENV MYSQL_ROOT_PASSWORD=root
ENV MYSQL_DATABASE=base

# Expose MySQL port
EXPOSE 3306

COPY init.sql /docker-entrypoint-initdb.d/