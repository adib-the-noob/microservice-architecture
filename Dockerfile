FROM python:3.10

RUN apt-get update && apt-get install -y \
    && apt-get install -y --no-install-recommends --no-install-suggests \
        build-essential \
        default-libmysqlclient-dev \
        && pip install --no-cache-dir --upgrade pip 

WORKDIR /app
COPY ./requirements.txt /app
RUN pip install --no-cache-dir -r /app/requirements.txt
COPY . /app

EXPOSE 5000
CMD [ "python3", "app.py" ]