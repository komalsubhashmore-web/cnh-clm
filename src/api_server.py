# api_server_ws.py  –  FastAPI backend for WebSocket UI
import os, time, json, logging, h5py, torch, asyncio
from pathlib import Path
from contextlib import asynccontextmanager

from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from transformers import AutoTokenizer, AutoModelForCausalLM
from fastapi import Request

from src.config import STORE_LOCATION, LLM_PATH
from src.llm.utils import cleanup
from src.llm.embedding_store import VectorStore
from src.llm.retrieval import retrieve_documents
from src.llm.generation import generate_text_stream
from fastapi.staticfiles import StaticFiles


# ───────── log to /app/logs/server.log ─────────
log_dir = os.path.join(os.path.dirname(__file__), "..", "logs")
os.makedirs(log_dir, exist_ok=True)
log_file = os.path.join(log_dir, "server.log")

logging.basicConfig(
    filename="log_file",
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
)


# ───────── startup: load vector store + model ONCE ─────────
@asynccontextmanager
async def lifespan(app: FastAPI):
    t0 = time.time()
    print(" Loading embeddings …")
    global embedding_store
    embedding_store = VectorStore()
    # with h5py.File(f"{STORE_LOCATION}/vectorstore/vectors.h5", "r") as f:
    #     for base in {k.rsplit('_', 1)[0] for k in f}:
    #         vecs = torch.tensor(f[f"{base}_vectors"][:], dtype=torch.float32, device="cuda")
    #         keys = [k.decode() for k in f[base][:]]
    #         if vecs.numel():
    #             embedding_store.add_database(base, vecs, keys)
    # print(f" Embeddings ready in {time.time()-t0:.1f}s")

    print(" Loading LLM …")
    global llm, tokenizer
    tokenizer = AutoTokenizer.from_pretrained(LLM_PATH, local_files_only=True)
    llm = AutoModelForCausalLM.from_pretrained(
        LLM_PATH,
        torch_dtype=torch.bfloat16,
        device_map="auto",
        attn_implementation="sdpa",
        low_cpu_mem_usage=True,
        local_files_only=True,
    )
    print(" LLM ready.")
    yield
    cleanup()

app = FastAPI(lifespan=lifespan)
static_dir = os.path.join(os.path.dirname(__file__), "static")
app.mount("/static", StaticFiles(directory=static_dir), name="static")


# ───────── basic routes ─────────
templates = Jinja2Templates(directory="src/templates")

@app.get("/", response_class=HTMLResponse)
async def root(request: Request):                             
    return templates.TemplateResponse("chatbot-ui.html", {"request": request})

@app.get("/health")                                    
async def health():
    return {"status": "ok"}

# ───────── WebSocket handler ─────────
RAG_SYSTEM_PROMPT = (
    "You are NIGHTFALL, an expert red-team assistant trained by AI Sweden's Cyber Language Model (CLM) team in adversarial simulation and cybersecurity threat emulation. IMPORTANT: While you may have been trained in the past, the year is 2025."
    "Your job is to support trained security professionals in evaluating and probing the defenses of authorized systems. "
    "Avoid vague generalities. Be direct, tactical, and scenario-aware. Be concise, direct, and to the point. If you can answer in a paragraph or less, do so. IMPORTANT: You should minimize output tokens as much as possible while maintaining helpfulness, quality, and accuracy. "
    "Focus on actionable, specific, context-aware guidance relevant to red-teaming professionals. \n\n IMPORTANT: The first thing you should output are one line summaries of the retrieved documents between a <begin_summary> and <end_summary> token. Make sure to include whether or not the documents are current and up to date, reliable, and relevant. \n\n" 
    "For example, <begin_summary>\n{document one summary} \n {document two summary} \n ... <end_summary>."
    "Use the retrieved documents only if you find them relevant, otherwise ignore them."
)

NO_RAG_SYSTEM_PROMPT = (
    "You are NIGHTFALL, an expert red-team assistant trained by AI Sweden's Cyber Language Model (CLM) team in adversarial simulation and cybersecurity threat emulation. IMPORTANT: While you may have been trained in the past, the year is 2025."
    "Your job is to support trained security professionals in evaluating and probing the defenses of authorized systems. "
    "Avoid vague generalities. Be direct, tactical, and scenario-aware. Be concise, direct, and to the point. If you can answer in a paragraph or less, do so. IMPORTANT: You should minimize output tokens as much as possible while maintaining helpfulness, quality, and accuracy. "
    "Focus on actionable, specific, context-aware guidance relevant to red-teaming professionals. "
)


def convert_messages_to_prompt(messages, paused=False, rag_docs=True):

    """Convert ChatML-style messages into flat prompt string."""
    prompt = f"[BOS]\n"
    if rag_docs:
        prompt += f"<start_of_turn>user\n{RAG_SYSTEM_PROMPT}<end_of_turn>\n"
    else:
        prompt += f"<start_of_turn>user\n{NO_RAG_SYSTEM_PROMPT}<end_of_turn>\n"
        
    for msg in messages:
        if not isinstance(msg, dict):
            print("Malformed message:", msg)
            raise TypeError(f"Expected dict in messages, but got {type(msg)}")

        role = msg["role"]
        content_blocks = msg["content"]
        content = "".join(block["text"] for block in content_blocks if block["type"] == "text")
        prompt += f"<start_of_turn>{role}\n{content}<end_of_turn>\n"
    if paused:
        prompt = prompt.removesuffix("<end_of_turn>\n")
    else:
        prompt += "<start_of_turn>model\n"
    return prompt



@app.websocket("/ws/generate")
async def ws_generate(ws: WebSocket):
    await ws.accept()
    print("WebSocket connected")
    cancel_event = asyncio.Event()
    history = []
    rag_flag = False

    async def send_json(obj):
        await ws.send_text(json.dumps(obj))

    async def listen_for_stop():
        while True:
            msg = await ws.receive_json()
            print(f" Message received in listener: {msg}")
            if msg.get("type") == "stop":
                print("STOP signal received")
                cancel_event.set()
                break

    try:
        while True:
            msg = await ws.receive_json()
            mtype = msg.get("type")

            if mtype == "clear":
                print("CLEAR signal received")
                history.clear()
                await send_json({"type": "info", "message": "History cleared."})
                continue

            if mtype == "resume":
                print("Resume Received")
                user_msg = msg.get("user", "").strip()
                assistant_msg = msg.get("assistant", "").strip()

                if not user_msg:
                    await send_json({"type": "error", "message": "empty user prompt"})
                    continue

                if history and history[-1]["role"] == "assistant":
                    history.pop()
                    if history and history[-1]["role"] == "user":
                        history.pop()

                history.append({
                    "role": "user",
                    "content": [{"type": "text", "text": user_msg}]
                })
                history.append({
                    "role": "assistant",
                    "content": [{"type": "text", "text": assistant_msg}]
                })

                full_prompt = convert_messages_to_prompt(history, paused=True, rag_docs=rag_flag)
                # full_prompt = assistant_msg
                cancel_event.clear()
                stop_listener = asyncio.create_task(listen_for_stop())
                bot_response = assistant_msg
                await send_json({"type": "answer_chunk", "data": bot_response})

                async for token in generate_text_stream(
                    full_prompt, tokenizer, llm,
                    cancel_event=cancel_event,
                    max_new_tokens=8192, temperature=0.7,
                    top_p=0.95, top_k=64, repitition_penalty=1.1
                ):
                    if cancel_event.is_set():
                        print("Generation stopped early by user (resume)")
                        break
                    await send_json({"type": "answer_chunk", "data": token})
                    bot_response += token

                try:
                    stop_listener.cancel()
                    await stop_listener
                except asyncio.CancelledError:
                    pass

                # if not cancel_event.is_set():
                history[-1] = ({
                    "role": "assistant",
                    "content": [{"type": "text", "text": bot_response}]
                })


                await send_json({"type": "done", "data": assistant_msg + bot_response})
                continue

            if mtype != "prompt":
                await send_json({"type": "error", "message": "unknown message type"})
                continue

            prompt_str = msg.get("prompt", "").strip()
            # editRequested = msg.get("edit", False)

            if not prompt_str:
                await send_json({"type": "error", "message": "empty prompt"})
                continue

            print(f"Prompt: {prompt_str}")

            # if editRequested:
            #     if history and history[-1]["role"] == "assistant":
            #         history.pop()
            #         if history and history[-1]["role"] == "user":
            #             history.pop()
            #     editRequested = False

            history.append({
                "role": "user",
                "content": [{"type": "text", "text": prompt_str}]
            })

            docs = retrieve_documents(prompt_str, embedding_store, topk=5, min_p=0.05)
   
            await send_json({"type": "rag_start"})
            if not docs:
                rag_flag = False
                await send_json({"type": "rag_chunk", "data": "No Documents Retrieved"})
            else:
                rag_flag = True
                for doc in docs:
                    await send_json({"type": "rag_chunk", "data": doc})
            await send_json({"type": "rag_end"})

            doc_context = f"The following references might help:\n{chr(10).join(docs)}\n\n" if docs else ""
            rag_context = f"{doc_context}Please provide a helpful answer to this question:\n{prompt_str}"
            history[-1]["content"][0]["text"] = rag_context

            full_prompt = convert_messages_to_prompt(history, rag_docs=rag_flag)
        

            cancel_event.clear()
            stop_listener = asyncio.create_task(listen_for_stop())
            bot_response = ""

            async for token in generate_text_stream(
                full_prompt, tokenizer, llm,
                cancel_event=cancel_event,
                max_new_tokens=8192, temperature=0.7,
                top_p=0.95, top_k=64, repitition_penalty=1.1
            ):
                if cancel_event.is_set():
                    print("Generation stopped early by user")
                    break
                await send_json({"type": "answer_chunk", "data": token})
                bot_response += token
                logging.info(f"This line is executed: {token}.")

            try:
                stop_listener.cancel()
                await stop_listener
            except asyncio.CancelledError:
                pass

            logging.info("Next line is executed")

            # if not cancel_event.is_set():
            history.append({
                "role": "assistant",
                "content": [{"type": "text", "text": bot_response}]
            })
            print(history)

            await send_json({"type": "done", "data": bot_response})

    except WebSocketDisconnect:
        print("WebSocket disconnected")
        cleanup()
    except Exception as e:
        logging.exception(f"WS error: {e}")
        await send_json({"type": "error", "message": "server exception"})
        cleanup()
