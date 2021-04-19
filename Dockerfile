FROM debian:testing

MAINTAINER Johan Lundberg <lundberg@sunet.se>

COPY . /opt/flask-ioc-lookup
COPY docker/setup.sh /setup.sh
COPY docker/start.sh /start.sh
RUN /setup.sh

EXPOSE 5000

WORKDIR /opt/flask-ioc-lookup

CMD ["bash", "/start.sh"]
