FROM debian:testing

MAINTAINER Johan Lundberg <lundberg@sunet.se>

COPY . /opt/flask-rpz-lookup
COPY docker/setup.sh /setup.sh
COPY docker/start.sh /start.sh
RUN /setup.sh

EXPOSE 5000

WORKDIR /opt/flask-rpz-lookup

CMD ["bash", "/start.sh"]
