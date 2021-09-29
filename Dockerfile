FROM ubuntu

ARG CONTAINER_TIMEZEON=Asia/Taipei
RUN ln -snf /usr/share/zoneinfo/$CONTAINER_TIMEZONE /etc/localtime && echo $CONTAINER_TIMEZONE > /etc/timezone

RUN apt update
RUN apt install sudo

COPY setup.sh /tmp/
RUN bash /tmp/setup.sh

WORKDIR /
CMD ["bash"]
