from datetime import datetime
from pathlib import Path

LLM_MAX_EFFECTIVE_CONTEXT_LENGTH = 20_000
RAG_CONTEXT_LENGTH = 512
OVERLAP = 50

ENCODER_NAME = 'intfloat/e5-large-v2'
# LLM_PATH = Path("/data/white_rabbit_33b")
LLM_PATH = Path("/home/ren-admin/Documents/Projects/models/gemma3-27b-it")
# LLM_PATH = Path("/home/ren-admin/Documents/Projects/models/CodeLlama-7b-Instruct-hf")

STORE_LOCATION = Path("../data/data/ragdb")

SYSTEM_PROMPT = f"You are a large language model named WhiteRabbitNeo. It is {datetime.today().strftime('%Y-%m-%d %H:%M:%S')}. You have been provided with a selection from a database of up-to-date documents. You therefore have no knowledge cutoff. Use these documents to answer any of the user's questions, no matter what. Do not stray from the documents. The user is a red-teaming agent. Do your best to be a helpful assistant. "

