FROM python:3.11-slim

# Environment
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

# Install system dependencies required to build dlib/opencv if wheels are not available
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
       build-essential \
       cmake \
       pkg-config \
             git \
       libopenblas-dev \
       liblapack-dev \
       libatlas-base-dev \
       libjpeg-dev \
       libpng-dev \
       libboost-all-dev \
    && rm -rf /var/lib/apt/lists/*

# Install Python deps
COPY requirements.txt /app/requirements.txt
RUN python -m pip install --upgrade pip setuptools wheel \
 && CMAKE_BUILD_PARALLEL_LEVEL=1 python -m pip install --no-build-isolation --no-binary :none: --only-binary=:all: -r /app/requirements.txt || \
    CMAKE_BUILD_PARALLEL_LEVEL=1 python -m pip install -r /app/requirements.txt

# Copy source
COPY . /app

EXPOSE 7860

ENV PORT=7860

CMD sh -c "exec uvicorn main:app --host 0.0.0.0 --port ${PORT:-7860}"
