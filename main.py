import os
import json
from fastapi import FastAPI, Request, Form, Depends, HTTPException, status
from fastapi.responses import HTMLResponse, RedirectResponse, FileResponse, JSONResponse
from fastapi.templating import Jinja2Templates
from fastapi.staticfiles import StaticFiles
from starlette.middleware.sessions import SessionMiddleware
from dotenv import load_dotenv
import aiofiles
import re
from datetime import datetime, timedelta

load_dotenv()

app = FastAPI()
app.add_middleware(SessionMiddleware, secret_key=os.getenv("SECRET_KEY", "supersecret"))

templates = Jinja2Templates(directory="templates")

SETTINGS_FILE = os.getenv("SETTINGS", "settings.json")
ADMIN_USER = os.getenv("ADMIN_USER")
ADMIN_PASS = os.getenv("ADMIN_PASS")

def get_settings():
    if not os.path.exists(SETTINGS_FILE):
        return {"logs": []}
    with open(SETTINGS_FILE, "r") as f:
        return json.load(f)

def save_settings(settings):
    with open(SETTINGS_FILE, "w") as f:
        json.dump(settings, f, indent=4)

def is_logged_in(request: Request):
    return request.session.get("user") == ADMIN_USER

def parse_log_line(line):
    # Regex to extract timestamp, IP, and username
    # 2026-01-06 09:34:17,365 - kc-portal - INFO - IP: 104.51.149.143 (Mac) - Anonymous - GET /
    match = re.match(r"^(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2},\d{3}) - .*? - .*? - IP: (.*?) \(.*?\) - (.*?) - ", line)
    if match:
        timestamp_str, ip, username = match.groups()
        try:
            # Parse timestamp, ignoring milliseconds for simplicity
            timestamp = datetime.strptime(timestamp_str.split(',')[0], "%Y-%m-%d %H:%M:%S")
            return timestamp, username, ip
        except ValueError:
            pass
    return None, None, None

@app.get("/", response_class=HTMLResponse)
async def index(request: Request):
    if not is_logged_in(request):
        return RedirectResponse(url="/login")
    settings = get_settings()
    return templates.TemplateResponse("index.html", {"request": request, "logs": settings["logs"], "logged_in": True})

@app.get("/login", response_class=HTMLResponse)
async def login_get(request: Request):
    return templates.TemplateResponse("login.html", {"request": request})

@app.post("/login")
async def login_post(request: Request, username: str = Form(...), password: str = Form(...)):
    if username == ADMIN_USER and password == ADMIN_PASS:
        request.session["user"] = username
        return RedirectResponse(url="/", status_code=status.HTTP_303_SEE_OTHER)
    return templates.TemplateResponse("login.html", {"request": request, "error": "Invalid credentials"})

@app.get("/logout")
async def logout(request: Request):
    request.session.clear()
    return RedirectResponse(url="/login")

@app.post("/add-log")
async def add_log(request: Request, name: str = Form(...), path: str = Form(...)):
    if not is_logged_in(request):
        raise HTTPException(status_code=401)
    settings = get_settings()
    settings["logs"].append({"name": name, "path": path})
    save_settings(settings)
    return RedirectResponse(url="/", status_code=status.HTTP_303_SEE_OTHER)

@app.post("/delete-log/{log_id}")
async def delete_log(request: Request, log_id: int):
    if not is_logged_in(request):
        raise HTTPException(status_code=401)
    settings = get_settings()
    if 0 <= log_id < len(settings["logs"]):
        settings["logs"].pop(log_id)
        save_settings(settings)
    return RedirectResponse(url="/", status_code=status.HTTP_303_SEE_OTHER)

@app.get("/view/{log_id}", response_class=HTMLResponse)
async def view_log(request: Request, log_id: int):
    if not is_logged_in(request):
        return RedirectResponse(url="/login")
    settings = get_settings()
    if 0 <= log_id < len(settings["logs"]):
        log = settings["logs"][log_id]
        return templates.TemplateResponse("view.html", {"request": request, "log_name": log["name"], "log_id": log_id, "logged_in": True})
    return RedirectResponse(url="/")

@app.get("/log-stream/{log_id}")
async def log_stream(request: Request, log_id: int, last_size: int = 0):
    if not is_logged_in(request):
        return JSONResponse({"error": "Unauthorized"}, status_code=401)
    
    settings = get_settings()
    if not (0 <= log_id < len(settings["logs"])):
        return JSONResponse({"error": "Not found"}, status_code=404)
    
    path = settings["logs"][log_id]["path"]
    if not os.path.exists(path):
        return JSONResponse({"content": "File not found", "new_size": 0})

    current_size = os.path.getsize(path)
    if current_size < last_size: # File rotated or truncated
        last_size = 0
    
    content = ""
    if current_size > last_size:
        async with aiofiles.open(path, mode='r') as f:
            await f.seek(last_size)
            content = await f.read()
            
    return {"content": content, "new_size": current_size}

@app.get("/analyze-log/{log_id}")
async def analyze_log(request: Request, log_id: int, period: str = "day"):
    if not is_logged_in(request):
        return JSONResponse({"error": "Unauthorized"}, status_code=401)
    
    settings = get_settings()
    if not (0 <= log_id < len(settings["logs"])):
        return JSONResponse({"error": "Not found"}, status_code=404)
    
    path = settings["logs"][log_id]["path"]
    if not os.path.exists(path):
        return JSONResponse({"error": "File not found"}, status_code=404)

    now = datetime.now()
    if period == "day":
        start_time = now - timedelta(days=1)
    elif period == "week":
        start_time = now - timedelta(days=7)
    elif period == "month":
        start_time = now - timedelta(days=30)
    else:
        return JSONResponse({"error": "Invalid period"}, status_code=400)

    unique_users = set()
    async with aiofiles.open(path, mode='r') as f:
        async for line in f:
            ts, user, ip = parse_log_line(line)
            if ts and ts >= start_time:
                if user == "Anonymous" and ip:
                    unique_users.add(ip)
                else:
                    unique_users.add(user)
    
    return {"users": sorted(list(unique_users))}

@app.get("/download/{log_id}")
async def download_log(request: Request, log_id: int):
    if not is_logged_in(request):
        raise HTTPException(status_code=401)
    settings = get_settings()
    if 0 <= log_id < len(settings["logs"]):
        path = settings["logs"][log_id]["path"]
        if os.path.exists(path):
            return FileResponse(path, filename=os.path.basename(path))
    raise HTTPException(status_code=404)

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
