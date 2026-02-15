# Use NVIDIA CUDA runtime base image
FROM nvidia/cuda:12.1.1-runtime-ubuntu22.04

# Install system dependencies
RUN apt-get update && apt-get install -y \
    python3 \
    python3-pip \
    python3-venv \
    git \
    curl \
    nano \
    libjpeg-dev \
    zlib1g-dev \
    libpng-dev && \
    ln -s /usr/bin/python3 /usr/bin/python && \
    apt-get clean && rm -rf /var/lib/apt/lists/*

# Set working directory to match your actual project structure
WORKDIR /src

# Create virtual environment
RUN python -m venv /src/venv

# Copy requirements and install dependencies inside venv
COPY requirements.txt .
RUN /src/venv/bin/pip install --upgrade pip && \
    /src/venv/bin/pip install -r requirements.txt

# Copy entire src directory contents
COPY src/ .

# Copy templates directory (if it exists outside src)
COPY src/templates /src/templates
COPY ./src/static /src/static


# Expose the port for FastAPI app
EXPOSE 8000

# Set environment variable for FastAPI reload (optional for dev)
ENV PYTHONUNBUFFERED=1

# Default command: Launch FastAPI app
CMD ["/src/venv/bin/uvicorn", "api_server:app", "--host", "0.0.0.0", "--port", "8000"]
# CMD ["gunicorn", "api_server-v3:app", "-k", "uvicorn.workers.UvicornWorker", "--workers", "2", "--bind", "0.0.0.0:8000", "--timeout", "120"]



# Default command: run your engine script
# CMD ["/src/venv/bin/python", "llm/engine.py"]


# Launch the FastAPI app from api_server.py
# CMD ["/src/venv/bin/uvicorn", "api_server:app", "--host", "0.0.0.0", "--port", "8000"]


# Start vLLM and then run engine.py after short wait
  # CMD bash -c "\
  # source /src/venv/bin/activate && \
  # /src/venv/bin/python -m vllm.entrypoints.openai.api_server \
  #   --model /data/LLM360_K2_local \
  #   --tokenizer /data/LLM360_K2_local \
  #   --tensor-parallel-size 4 & \
  # echo 'Waiting for vLLM to start...' && \
  # until curl -s http://localhost:8000/v1/completions > /dev/null; do sleep 5; done && \
  # echo 'vLLM is ready!'"
  # echo 'vLLM is ready!' && \
  # /src/venv/bin/python run.py"



  # Run the container indefinetely
 
  # For k2 model
  # CMD bash -c "\
  # source /src/venv/bin/activate && \
  # /src/venv/bin/python -m vllm.entrypoints.openai.api_server \
  #   --model /data/LLM360_K2_local \
  #   --tokenizer /data/LLM360_K2_local \
  #   --max-model-len 4096 \
  #   --gpu-memory-utilization 0.95 \
  #   --tensor-parallel-size 4 > /src/vllm.log 2>&1 & \
  # echo 'Waiting for vLLM to start...' && \
  # until curl -s http://localhost:8000/v1/completions > /dev/null; do sleep 5; done && \
  # echo 'vLLM is ready!' && \
  # tail -f /dev/null"

  #For gemma model
# CMD bash -c "\
#   source /src/venv/bin/activate && \
#   /src/venv/bin/python -m vllm.entrypoints.openai.api_server \
#     --model /data/gemma3-27b \
#     --tokenizer /data/gemma3-27b \
#     --tensor-parallel-size 4 \
#     --gpu-memory-utilization 0.95 \
#     --host 0.0.0.0 > /src/vllm.log 2>&1 & \
#   echo 'Waiting for vLLM to start...' && \
#   until curl -s http://localhost:8000/v1/models > /dev/null; do sleep 5; done && \
#   echo 'vLLM is ready!' && \
#   tail -f /src/vllm.log"




  # CMD bash -c "\
#   python3 -m vllm.entrypoints.openai.api_server \
#     --model /data/LLM360_K2_local \
#     --tokenizer /data/LLM360_K2_local \
#     --tensor-parallel-size 4 & \
#   echo 'Waiting for vLLM to start...' && \
#   until curl -s http://localhost:8000/v1/completions > /dev/null; do sleep 5; done && \
#   echo 'vLLM is ready!' && \
#   python3 run.py"
