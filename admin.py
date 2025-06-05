from fastapi import FastAPI, Request, Form, UploadFile, File
from fastapi.templating import Jinja2Templates
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
import httpx
import os
from fastapi.responses import Response
from fastapi import Cookie, Depends, HTTPException
from fastapi.responses import RedirectResponse
from fastapi.requests import Request
import asyncio
from functools import wraps
from datetime import datetime

app = FastAPI()
templates = Jinja2Templates(directory="templates")

# Serve optional static files if present
if os.path.isdir("static"):
    app.mount("/static", StaticFiles(directory="static"), name="static")

# Base URL of the FastAPI backend
# Can be overridden with the API_BASE_URL environment variable
API_BASE_URL = os.getenv("API_BASE_URL", "https://api.dwanalytics.io")

class AdminAuthException(Exception):
    pass

def require_admin_token(admin_token: str = Cookie(None)):
    if not admin_token:
        raise AdminAuthException("No admin token")
    return admin_token

@app.exception_handler(AdminAuthException)
async def admin_auth_exception_handler(request: Request, exc: AdminAuthException):
    # Don't redirect if already on login page
    if request.url.path == "/admin/login":
        return templates.TemplateResponse(
            "admin_login.html",
            {"request": request, "error": None, "api_url": API_BASE_URL}
        )
    return RedirectResponse(url="/admin/login", status_code=303)

# Add retry decorator
def async_retry(retries=3, delay=1):
    def decorator(func):
        @wraps(func)
        async def wrapper(*args, **kwargs):
            last_exception = None
            for attempt in range(retries):
                try:
                    return await func(*args, **kwargs)
                except httpx.RequestError as e:
                    last_exception = e
                    if attempt < retries - 1:
                        await asyncio.sleep(delay)
            raise last_exception
        return wrapper
    return decorator

# Update client settings
async def get_api_client():
    return httpx.AsyncClient(
        timeout=httpx.Timeout(30.0),
        limits=httpx.Limits(max_keepalive_connections=5, max_connections=10),
        verify=False  # Only during development
    )

# Add safe fetch helper
async def safe_fetch(client, url, headers):
    try:
        response = await client.get(url, headers=headers, follow_redirects=True)
        return safe_json(response)
    except Exception as e:
        print(f"Error fetching {url}: {str(e)}")
        return None

# Update safe_json
def safe_json(resp):
    try:
        if resp and resp.status_code == 200:
            return resp.json()
        if resp:
            print(f"API Error: {resp.status_code} - {resp.text}")
    except Exception as e:
        print(f"JSON parsing error: {str(e)}")
    return None

@app.get("/")
async def root():
    """Redirect root to admin login"""
    return RedirectResponse(url="/admin/login", status_code=303)

@app.get("/admin/login", response_class=HTMLResponse)
async def admin_login_form(
    request: Request,
    error: str = None,
    admin_token: str = Cookie(None)
):
    # If already logged in with valid admin token, redirect to dashboard
    if admin_token:
        async with httpx.AsyncClient() as client:
            try:
                headers = {"Authorization": f"Bearer {admin_token}"}
                me_response = await client.get(f"{API_BASE_URL}/users/me", headers=headers)
                if me_response.status_code == 200 and me_response.json().get("is_admin"):
                    return RedirectResponse(url="/admin", status_code=303)
            except:
                pass
    
    # Otherwise show login page
    return templates.TemplateResponse(
        "admin_login.html",
        {"request": request, "error": error, "api_url": API_BASE_URL}
    )

@app.post("/admin/login", response_class=HTMLResponse)
async def admin_login(
    request: Request,
    phone_number: str = Form(...),
    otp: str = Form(...)
):
    async with httpx.AsyncClient() as client:
        try:
            # Step 1: Verify OTP
            data = {"username": phone_number, "password": otp}
            headers = {"Content-Type": "application/x-www-form-urlencoded"}
            response = await client.post(
                f"{API_BASE_URL}/users/verify-otp",
                data=data,
                headers=headers
            )

            if response.status_code != 200:
                return templates.TemplateResponse(
                    "admin_login.html",
                    {
                        "request": request,
                        "error": "Invalid credentials",
                        "api_url": API_BASE_URL
                    }
                )

            # Step 2: Get token and verify admin status
            token = response.json().get("access_token")
            admin_headers = {"Authorization": f"Bearer {token}"}
            
            # Verify admin status
            me_response = await client.get(
                f"{API_BASE_URL}/users/me",
                headers=admin_headers
            )
            
            if me_response.status_code != 200 or not me_response.json().get("is_admin"):
                return templates.TemplateResponse(
                    "admin_login.html",
                    {
                        "request": request,
                        "error": "Not authorized as admin",
                        "api_url": API_BASE_URL
                    }
                )

            # Step 3: Set cookie and redirect
            response = RedirectResponse(url="/admin", status_code=303)
            response.set_cookie(
                key="admin_token",
                value=token,
                httponly=True,
                secure=True,
                samesite="lax",
                max_age=1800  # 30 minutes
            )
            return response

        except Exception as e:
            print(f"Login error: {str(e)}")
            return templates.TemplateResponse(
                "admin_login.html",
                {
                    "request": request,
                    "error": f"Login failed: {str(e)}",
                    "api_url": API_BASE_URL
                }
            )

@app.get("/admin", response_class=HTMLResponse)
@async_retry(retries=3)
async def admin_dashboard(
    request: Request, 
    admin_token: str = Depends(require_admin_token)
):
    async with await get_api_client() as client:
        try:
            # Verify admin status
            headers = {"Authorization": f"Bearer {admin_token}"}
            me_response = await client.get(
                f"{API_BASE_URL}/users/me", 
                headers=headers,
                follow_redirects=True
            )
            
            if me_response.status_code != 200 or not me_response.json().get("is_admin"):
                return RedirectResponse(url="/admin/login", status_code=303)

            # Fetch dashboard data with error handling
            [stats, users, posts, verses, donations, events] = await asyncio.gather(
                *[
                    safe_fetch(client, f"{API_BASE_URL}/admin/stats", headers),
                    safe_fetch(client, f"{API_BASE_URL}/admin/users", headers),
                    safe_fetch(client, f"{API_BASE_URL}/admin/posts", headers),
                    safe_fetch(client, f"{API_BASE_URL}/admin/verses", headers),
                    safe_fetch(client, f"{API_BASE_URL}/admin/donations", headers),
                    safe_fetch(client, f"{API_BASE_URL}/admin/events", headers)
                ],
                return_exceptions=True
            )

            return templates.TemplateResponse(
                "admin.html",
                {
                    "request": request,
                    "stats": stats if not isinstance(stats, Exception) else {},
                    "users": users if not isinstance(users, Exception) else [],
                    "posts": posts if not isinstance(posts, Exception) else [],
                    "verses": verses if not isinstance(verses, Exception) else [],
                    "donations": donations if not isinstance(donations, Exception) else [],
                    "events": events if not isinstance(events, Exception) else [],
                    "error": None,
                    "api_url": API_BASE_URL
                }
            )

        except Exception as e:
            print(f"Dashboard error: {str(e)}")
            return templates.TemplateResponse(
                "admin.html",
                {
                    "request": request,
                    "error": f"API connection error: {str(e)}",
                    "stats": {},
                    "users": [],
                    "posts": [],
                    "verses": [],
                    "donations": [],
                    "events": []
                }
            )

@app.get("/admin/logout")
async def admin_logout():
    response = RedirectResponse(url="/admin/login", status_code=303)
    response.delete_cookie(key="admin_token")
    return response

# For all POST/DELETE admin actions, add admin_token: str = Cookie(None) and use it for headers
@app.post("/admin/delete-post/{post_id}")
async def delete_post(post_id: str, admin_token: str = Depends(require_admin_token)):
    headers = {"Authorization": f"Bearer {admin_token}"}
    async with httpx.AsyncClient() as client:
        await client.delete(f"{API_BASE_URL}/admin/posts/{post_id}", headers=headers)
    return RedirectResponse(url="/admin", status_code=303)

@app.post("/admin/delete-user/{user_id}")
async def delete_user(user_id: str, admin_token: str = Depends(require_admin_token)):
    headers = {"Authorization": f"Bearer {admin_token}"}
    async with httpx.AsyncClient() as client:
        await client.delete(f"{API_BASE_URL}/admin/users/{user_id}", headers=headers)
    return RedirectResponse(url="/admin", status_code=303)

@app.post("/admin/delete-verse/{verse_id}")
async def delete_verse(verse_id: str, admin_token: str = Depends(require_admin_token)):
    headers = {"Authorization": f"Bearer {admin_token}"}
    async with httpx.AsyncClient() as client:
        await client.delete(f"{API_BASE_URL}/admin/verses/{verse_id}", headers=headers)
    return RedirectResponse(url="/admin", status_code=303)

@app.post("/admin/delete-event/{event_id}")
async def delete_event(event_id: str, admin_token: str = Depends(require_admin_token)):
    headers = {"Authorization": f"Bearer {admin_token}"}
    async with httpx.AsyncClient() as client:
        await client.delete(f"{API_BASE_URL}/admin/events/{event_id}", headers=headers)
    return RedirectResponse(url="/admin", status_code=303)

@app.post("/admin/daily-verse/create")
async def create_verse(
    request: Request,
    title: str = Form(...),
    verse_text: str = Form(...),
    reflection: str = Form(None),
    display_date: str = Form(...),
    image: UploadFile = None,
    admin_token: str = Depends(require_admin_token)
):
    headers = {"Authorization": f"Bearer {admin_token}"}
    
    # Convert display_date to ISO format
    try:
        # Parse the date string (assuming format YYYY-MM-DD)
        parsed_date = datetime.strptime(display_date, "%Y-%m-%d")
        iso_date = parsed_date.isoformat()
    except ValueError:
        return templates.TemplateResponse(
            "admin.html",
            {
                "request": request,
                "error": "Invalid date format. Use YYYY-MM-DD",
                "stats": {},
                "users": [],
                "posts": [],
                "verses": [],
                "donations": [],
                "events": []
            }
        )

    form_data = {
        "title": title,
        "verse_text": verse_text,
        "reflection": reflection,
        "display_date": iso_date
    }
    
    files = {}
    if image:
        files = {"image": (image.filename, image.file, image.content_type)}
    
    async with httpx.AsyncClient() as client:
        response = await client.post(
            f"{API_BASE_URL}/daily-verse/create",
            data=form_data,
            files=files,
            headers=headers
        )
        if response.status_code != 200:
            return templates.TemplateResponse(
                "admin.html",
                {
                    "request": request,
                    "error": f"Failed to create verse: {response.text}",
                    "stats": {},
                    "users": [],
                    "posts": [],
                    "verses": [],
                    "donations": [],
                    "events": []
                }
            )
    return RedirectResponse(url="/admin", status_code=303)

@app.post("/admin/events/create")
async def create_event(
    request: Request,
    title: str = Form(...),
    category: str = Form(...),
    event_date: str = Form(...),
    description: str = Form(...),
    organizer: str = Form(...),
    image: UploadFile = None,
    admin_token: str = Depends(require_admin_token)
):
    headers = {"Authorization": f"Bearer {admin_token}"}
    
    form_data = {
        "title": title,
        "category": category,
        "event_date": event_date,
        "description": description,
        "organizer": organizer,
    }

    files = {}
    if image:
        files = {"image": (image.filename, image.file, image.content_type)}

    async with httpx.AsyncClient() as client:
        response = await client.post(
            f"{API_BASE_URL}/events/create",
            data=form_data,
            files=files,
            headers=headers
        )
        
        if response.status_code != 200:
            return templates.TemplateResponse(
                "admin.html",
                {
                    "request": request,
                    "error": f"Failed to create event: {response.text}",
                    "stats": {},
                    "users": [],
                    "posts": [],
                    "verses": [],
                    "donations": [],
                    "events": []
                }
            )
            
    return RedirectResponse(url="/admin", status_code=303)

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("admin:app", host="0.0.0.0", port=8001, reload=True)
