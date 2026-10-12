# BUILDER STAGE
FROM python:3.11-slim AS builder

WORKDIR /build

# Copy requirements and install dependencies
COPY services/ml-analytics/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt grpcio-tools

# Copy proto definitions
COPY proto ./proto

# Generate Python bindings
RUN mkdir -p generated/python && \
    python -m grpc_tools.protoc --proto_path=proto \
           --python_out=generated/python \
           --grpc_python_out=generated/python \
           proto/kaaladrishti/v1/platform.proto

# Fix relative import in the generated grpc file
RUN sed -i 's/from kaaladrishti.v1 import platform_pb2/from generated.python.kaaladrishti.v1 import platform_pb2/g' \
    generated/python/kaaladrishti/v1/platform_pb2_grpc.py

# FINAL STAGE
FROM python:3.11-slim

WORKDIR /app

# Copy python packages from builder
COPY --from=builder /usr/local/lib/python3.11/site-packages /usr/local/lib/python3.11/site-packages
COPY --from=builder /usr/local/bin /usr/local/bin

# Copy generated bindings
COPY --from=builder /build/generated/python /app/generated/python

# Copy application source code
COPY services/ml-analytics/app /app/app
COPY services/ml-analytics/training /app/training

# Set PYTHONPATH so absolute imports work
ENV PYTHONPATH="/app"

EXPOSE 50051

ENTRYPOINT ["python", "-m", "app.grpc_server"]
