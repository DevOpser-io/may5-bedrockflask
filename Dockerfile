# start by pulling the python image
FROM python:3.11.6-slim-bullseye

# Create a non-root user with UID 1000
RUN useradd -m -u 1000 appuser

ENV PATH="/usr/local/bin:$PATH"
ENV DOCKER_BUILDKIT=1
ENV FLASK_APP=run
ENV FLASK_ENV=production
ARG FLASK_SECRET_NAME
ARG REDIS_URL
ARG REGION
ARG CACHE_VERSION
ARG DB_NAME_SECRET_NAME
ARG DB_USER_SECRET_NAME
ARG DB_PASSWORD_SECRET_NAME
ARG DB_HOST_SECRET_NAME
ARG DB_PORT_SECRET_NAME
ARG MAIL_PASSWORD_SECRET_NAME
ARG MAIL_USERNAME
ARG MAIL_DEFAULT_SENDER
ARG ADDITIONAL_SECRETS
ARG ADMIN_USERS_SECRET_NAME
ARG CUSTOMER_CROSS_ACCOUNT_ROLE_ARN

ENV CACHE_VERSION=${CACHE_VERSION}
ENV FLASK_SECRET_NAME=${FLASK_SECRET_NAME}
ENV REDIS_URL=${REDIS_URL}
ENV REGION=${REGION}
ENV DB_NAME_SECRET_NAME=${DB_NAME_SECRET_NAME}
ENV DB_USER_SECRET_NAME=${DB_USER_SECRET_NAME}
ENV DB_PASSWORD_SECRET_NAME=${DB_PASSWORD_SECRET_NAME}
ENV DB_HOST_SECRET_NAME=${DB_HOST_SECRET_NAME}
ENV DB_PORT_SECRET_NAME=${DB_PORT_SECRET_NAME}
ENV MAIL_PASSWORD_SECRET_NAME=${MAIL_PASSWORD_SECRET_NAME}
ENV ADMIN_USERS_SECRET_NAME=${ADMIN_USERS_SECRET_NAME}
ENV CUSTOMER_CROSS_ACCOUNT_ROLE_ARN=${CUSTOMER_CROSS_ACCOUNT_ROLE_ARN}


ENV MAIL_SERVER=${MAIL_SERVER}
ENV MAIL_PORT=${MAIL_PORT}
ENV MAIL_USE_TLS=${MAIL_USE_TLS}
ENV MAIL_USERNAME=${MAIL_USERNAME}
ENV MAIL_DEFAULT_SENDER=${MAIL_DEFAULT_SENDER}

ENV ADDITIONAL_SECRETS=${ADDITIONAL_SECRETS}

# Create necessary directories and set permissions
RUN mkdir -p /app /app/instance /app/logs /data && \
    chown -R appuser:appuser /app /data

# switch working directory
WORKDIR /app

# copy the requirements file into the image
COPY --chown=appuser:appuser ./app/requirements.txt /app/requirements.txt

# install the dependencies and packages in the requirements file
RUN pip3.11 install -r requirements.txt

# copy every content from the local file to the image
COPY --chown=appuser:appuser . /app

ENV FLASK_RUN_HOST=0.0.0.0

EXPOSE 8000

# Switch to the non-root user
USER appuser

# configure the container to run in an executed manner
ENTRYPOINT ["gunicorn", "--workers", "2", "--threads", "3", "--worker-class", "gthread", "--worker-tmp-dir", "/dev/shm", "--log-level", "info", "--access-logfile", "-", "--error-logfile", "-", "--capture-output", "--enable-stdio-inheritance", "run:app", "--bind=0.0.0.0:8000"]
