"""Offline MiniLM embeddings and the durable, single-threaded indexing worker."""

import logging
import math
import os
import threading
from pathlib import Path

from hub.store import now_us

MODEL = {
    "name": "Qdrant/all-MiniLM-L6-v2-onnx",
    "fastembed_name": "sentence-transformers/all-MiniLM-L6-v2",
    "revision": "d13954661f83248295ba75c1ed411eef3b7b936e",
    "dim": 384,
}
MODEL_KEY = f"{MODEL['name']}@{MODEL['revision']}"
MAX_WORDPIECES = 256
OVERLAP = 32
MAX_ATTEMPTS = 5
log = logging.getLogger("hub.embed")


class Embedder:
    """Lazy and read-only. A bad or absent image model degrades to FTS retrieval."""

    def __init__(self, path=None):
        self.path = Path(path or os.environ.get("HUB_MODEL_DIR", "/opt/models/minilm"))
        self._model = None
        self._tokenizer = None
        self._lock = threading.Lock()

    def load(self):
        if self._model is not None:
            return self._model
        with self._lock:
            if self._model is not None:
                return self._model
            try:
                if not (self.path / "model.onnx").is_file():
                    return None
                from fastembed import TextEmbedding
                from tokenizers import Tokenizer

                tokenizer = Tokenizer.from_file(str(self.path / "tokenizer.json"))
                model = TextEmbedding(
                    model_name=MODEL["fastembed_name"],
                    specific_model_path=str(self.path),
                    local_files_only=True,
                    threads=1,
                )
                self._tokenizer, self._model = tokenizer, model
                return model
            except Exception:
                log.exception("offline embedding model unavailable")
                return None

    def chunks(self, value):
        if not isinstance(value, str) or not value:
            return []
        if self.load() is None:
            return []
        ids = self._tokenizer.encode(value, add_special_tokens=False).ids
        width, step = MAX_WORDPIECES - 2, MAX_WORDPIECES - 2 - OVERLAP
        return [
            self._tokenizer.decode(ids[start : start + width], skip_special_tokens=True)
            for start in range(0, len(ids), step)
            if start == 0 or start + OVERLAP < len(ids)
        ]

    def embed(self, values):
        model = self.load()
        if model is None:
            return None
        try:
            vectors = []
            for value in model.embed(values, batch_size=8):
                vector = [float(x) for x in value]
                if len(vector) != MODEL["dim"]:
                    raise ValueError("embedding dimension mismatch")
                norm = math.sqrt(sum(x * x for x in vector))
                if not math.isfinite(norm) or norm <= 0:
                    raise ValueError("invalid embedding norm")
                vectors.append([x / norm for x in vector])
            return vectors
        except Exception:
            log.exception("embedding inference failed")
            return None


class Worker:
    """One bounded background worker. Pending rows are the crash-safe claim."""

    def __init__(self, store, embedder=None):
        self.store = store
        self.embedder = embedder or Embedder()
        self.stop_event = threading.Event()
        self.thread = threading.Thread(target=self.run, name="hub-embed", daemon=True)

    def start(self):
        self.thread.start()

    def stop(self):
        self.stop_event.set()
        self.thread.join(timeout=10)

    def run(self):
        from hub.index import current_text, fail_job, finish_job, pending_job

        while not self.stop_event.is_set():
            job = None
            try:
                if self.embedder.load() is None:
                    self.stop_event.wait(2)
                    continue
                job = self.store.read(pending_job)
                if job is None:
                    self.stop_event.wait(0.25)
                    continue
                source = self.store.read(lambda con, current=job: current_text(con, current))
                if source is None:
                    finish_job(self.store, job, [])
                    continue
                values = self.embedder.chunks(source)
                vectors = self.embedder.embed(values) if values else []
                if vectors is None:
                    fail_job(self.store, job, now_us(), MAX_ATTEMPTS)
                    self.stop_event.wait(0.1)
                    continue
                finish_job(self.store, job, vectors)
            except Exception:
                log.exception("embedding worker job failed")
                if job is not None:
                    try:
                        fail_job(self.store, job, now_us(), MAX_ATTEMPTS)
                    except Exception:
                        log.exception("embedding worker could not record job failure")
                self.stop_event.wait(1)
