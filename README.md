# cnh-clm: Large Language Model
A modular, containerized pipeline that combines Large Language Models (LLMs), OCR, CVE parsing, and retrieval-based generation into a unified chatbot interface for cybersecurity red teaming support.

## Features
* Web-based Chatbot Interface using FastAPI + WebSockets

* LLM Integration with customizable prompt & generation backends

* OCR Extraction to parse text from cybersecurity documents

* CVE/ExploitDB Preprocessing for use in retrieval-augmented generation

* Vector Store Retrieval using custom or pretrained embedding models

* Interactive Notebooks for experimentation and finetuning

* Docker Support for seamless containerized deployment


## Getting Started

1. Clone the Repository
    git clone https://github.com/iamasr9999/cnh-clm.git
    cd cnh-clm

2. Install Dependencies
   * pip install -r requirements.txt

    Or use Docker

    — command to build docker
    * docker build -t tag_name .


    — Push to docker hub
    * docker login

    — Tag your image
    * docker tag tag_name  docker_username/repository:tag

    — push it
    * docker push docker_username/repository:tag

3. Run the Application on server with uvicorn
    - While starting the job make sure to open port 8000 and 22
    - This command "/src/venv/bin/uvicorn", "api_server:app", "--host", "0.0.0.0", "--port", "8000" is already in the dockerfile so when you start a job the process stats.
    - Visit http://localhost:8000 to access UI


## LLM Architecture
    Embedding Store: Converts input data into vector form

    Retriever: Selects relevant context based on input query

    Generator: Produces final LLM response

    Supports plug-and-play with other models


## Chatbot UI
    FastAPI serves chatbot-ui.html, allowing:

    Prompt submission and streaming response

    Resume/edit previous messages

    Visual context (images from static/)

## Logs
    Logs for server activity are saved to:
    - logs/server.log


- [cnh-clm: Large Language Model](#cnh-clm-large-language-model)
  - [Features](#features)
  - [Getting Started](#getting-started)
  - [LLM Architecture](#llm-architecture)
  - [Chatbot UI](#chatbot-ui)
  - [Logs](#logs)





