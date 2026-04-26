import re
from fastapi import FastAPI
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware

from routers.hash_router     import router as hash_router
from dashboard.router        import router as dashboard_router
from routers.domain_router   import router as domain_router
from routers.url_router      import router as url_router
from routers.ip_router       import router as ip_router
from routers.mail_router     import router as mail_router
from routers.cve_router      import router as cve_router
from routers.ioc_router      import router as ioc_router
from routers.auth_router     import router as auth_router
from routers.history_router  import router as history_router
from routers.stats_router    import router as stats_router
from routers.export_router   import router as export_router
from routers.chat_router     import router as chat_router
from routers.chatbot_router  import router as chatbot_router

from middlewares.rate_limit    import rate_limit_middleware
from middlewares.activity_log  import activity_log_middleware
from database.db               import init_db

app = FastAPI(
    title="Threat Intelligence Platform",
    description="Plateforme TI — IOC enrichment + Chatbot IA",
    version="2.0"
)

init_db()

from fastapi.middleware.cors import CORSMiddleware

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173"],  
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Middlewares
app.add_middleware(BaseHTTPMiddleware, dispatch=rate_limit_middleware)
app.add_middleware(BaseHTTPMiddleware, dispatch=activity_log_middleware)

# Auth (public)
app.include_router(auth_router,     prefix="/auth",      tags=["Authentication"])

# IOC enrichment
app.include_router(hash_router,     prefix="/hash",      tags=["Hash Enrichment"])
app.include_router(domain_router,   prefix="/domain",    tags=["Domain Enrichment"])
app.include_router(ip_router,       prefix="/ip",        tags=["IP Reputation"])
app.include_router(url_router,      prefix="/url",       tags=["URL Reputation"])
app.include_router(mail_router,     prefix="/mail",      tags=["Mail Reputation"])
app.include_router(cve_router,      prefix="/cve",       tags=["CVE Lookup"])
app.include_router(ioc_router,      prefix="/ioc",       tags=["IOC Analysis"])

# Chatbot Racha
app.include_router(chatbot_router,  prefix="/chatbot",   tags=["Chatbot"])

# Sessions chat authentifiees Yas
app.include_router(chat_router,     prefix="/chat",      tags=["Chat Sessions"])

# Historique / Stats / Export
app.include_router(history_router,  prefix="/history",   tags=["History"])
app.include_router(stats_router,    prefix="/stats",     tags=["Stats"])
app.include_router(export_router,   prefix="/export",    tags=["Export"])

# Dashboard
app.include_router(dashboard_router, prefix="/dashboard", tags=["Dashboard"])

@app.get("/", tags=["Health"])
def root():
    return {"status": "ok", "message": "Threat Intelligence Platform v2.0 running"}

@app.get("/reindex", tags=["Health"])
def reindex():
    from rag.rag_indexer import index_all_sources
    total = index_all_sources()
    return {"status": "ok", "total": total}
