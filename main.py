import os
import time
import logging
from datetime import datetime
from typing import Dict
import httpx
from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

# ==============================
# CONFIG
# ==============================

OPENAI_BASE_URL = "https://aipipe.org/openai/v1"
OPENAI_API_KEY = "eyJhbGciOiJIUzI1NiJ9.eyJlbWFpbCI6IjIyZjIwMDA5ODRAZHMuc3R1ZHkuaWl0bS5hYy5pbiJ9.G7srIOp35q_kYBkoQ9D4CusHekbXlHbCvsP4YiuaoRM"
MODERATION_MODEL = "omni-moderation-latest"

CONFIDENCE_THRESHOLD = 0.9
RATE_LIMIT = 20  # max requests per user per minute

# ==============================
# APP SETUP
# ==============================

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["POST", "OPTIONS"],
    allow_headers=["*"],
)

logging.basicConfig(
    filename="security.log",
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s"
)

# Simple in-memory rate limiter
user_requests: Dict[str, list] = {}

# ==============================
# REQUEST MODEL
# ==============================

class SecurityRequest(BaseModel):
    userId: str
    input: str
    category: str

# ==============================
# MODERATION FUNCTION
# ==============================

# async def moderate_text(text: str):
#     try:
#         async with httpx.AsyncClient() as client:
#             response = await client.post(
#                 f"{OPENAI_BASE_URL}/moderations",
#                 headers={
#                     "Authorization": f"Bearer {OPENAI_API_KEY}",
#                     "Content-Type": "application/json"
#                 },
#                 json={
#                     "model": MODERATION_MODEL,
#                     "input": text
#                 },
#                 timeout=30
#             )
#             response.raise_for_status()
#             return response.json()
#     except Exception:
#         raise HTTPException(status_code=400, detail="Moderation service unavailable")

async def moderate_text(text: str):
    try:
        async with httpx.AsyncClient() as client:
            response = await client.post(
                f"{OPENAI_BASE_URL}/moderations",
                headers={
                    "Authorization": f"Bearer {OPENAI_API_KEY}",
                    "Content-Type": "application/json"
                },
                json={
                    "model": MODERATION_MODEL,
                    "input": text
                },
                timeout=30
            )
            response.raise_for_status()
            return response.json(), None
    except Exception:
        return None, "Moderation service unavailable"


# ==============================
# RATE LIMIT CHECK
# ==============================

def check_rate_limit(user_id: str):
    now = time.time()
    window = 60  # seconds

    if user_id not in user_requests:
        user_requests[user_id] = []

    # Remove expired timestamps
    user_requests[user_id] = [
        t for t in user_requests[user_id] if now - t < window
    ]

    if len(user_requests[user_id]) >= RATE_LIMIT:
        raise HTTPException(status_code=429, detail="Rate limit exceeded")

    user_requests[user_id].append(now)

# ==============================
# ENDPOINT
# ==============================

# 
@app.post("/validate")
async def validate_content(req: SecurityRequest):

    if not req.input.strip():
        return {
            "blocked": True,
            "reason": "Input cannot be empty",
            "sanitizedOutput": None,
            "confidence": 0.0
        }

    try:
        check_rate_limit(req.userId)
    except HTTPException:
        return {
            "blocked": True,
            "reason": "Rate limit exceeded",
            "sanitizedOutput": None,
            "confidence": 0.0
        }

    moderation_result, error = await moderate_text(req.input)

    if error:
        return {
            "blocked": True,
            "reason": error,
            "sanitizedOutput": None,
            "confidence": 0.0
        }

    flagged = False
    confidence = 0.0
    reason = "Input passed all security checks"

    category_scores = moderation_result["results"][0]["category_scores"]

    for category, score in category_scores.items():
        if score > CONFIDENCE_THRESHOLD:
            flagged = True
            confidence = score
            reason = f"Blocked due to {category}"
            break

    if flagged:
        logging.warning(
            f"Blocked content from user {req.userId} | reason={reason}"
        )
        return {
            "blocked": True,
            "reason": reason,
            "sanitizedOutput": None,
            "confidence": round(confidence, 2)
        }

    return {
        "blocked": False,
        "reason": reason,
        "sanitizedOutput": req.input,
        "confidence": 1.0
    }
