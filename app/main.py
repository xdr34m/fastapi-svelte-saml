from fastapi import FastAPI, Request, Form, HTTPException
from typing import Optional
from starlette.responses import RedirectResponse, HTMLResponse
import uvicorn
import os
from onelogin.saml2.auth import OneLogin_Saml2_Auth
from onelogin.saml2.settings import OneLogin_Saml2_Settings
from onelogin.saml2.utils import OneLogin_Saml2_Utils

app = FastAPI(root_path="/api")

# Helper function to prepare SAML request
def prepare_saml_request(request: Request):
    form = {
        "https": "on" if request.url.scheme == "https" else "off",
        "http_host": request.client.host,
        "script_name": request.scope.get("root_path", ""),
        "server_port": request.url.port,
        "path_info": request.url.path,
        "get_data": request.query_params,
        "post_data": request.form(),
    }
    return OneLogin_Saml2_Auth(form, custom_base_path=os.path.join(os.getcwd(), "app" ,"saml"))

@app.get("/")
async def index():
    return HTMLResponse(
        "<h1>Welcome to FastAPI SAML Example</h1>"
        "<a href='/api/sso/login/'>Login via SAML</a>"
    )

@app.get("/metadata/")
async def metadata():
    from onelogin.saml2.settings import OneLogin_Saml2_Settings

    settings = OneLogin_Saml2_Settings(
        custom_base_path=os.path.join(os.getcwd(), "app", "saml"), sp_validation_only=True
    )
    metadata = settings.get_sp_metadata()
    errors = settings.validate_metadata(metadata)
    if errors:
        raise HTTPException(status_code=500, detail=", ".join(errors))
    return HTMLResponse(content=metadata, media_type="application/xml")

@app.get("/sso/login/")
async def sso_login(request: Request):
    auth = prepare_saml_request(request)
    login_url = auth.login()
    return RedirectResponse(url=login_url)

@app.post("/sso/acs/")
async def acs(request: Request):
    auth = prepare_saml_request(request)
    request_body = await request.body()
    auth.process_response(request_body)

    errors = auth.get_errors()
    if errors:
        raise HTTPException(status_code=400, detail=", ".join(errors))

    if not auth.is_authenticated():
        raise HTTPException(status_code=401, detail="User not authenticated via SAML.")

    # Extract user details
    user_data = {
        "name_id": auth.get_nameid(),
        "session_index": auth.get_session_index(),
        "attributes": auth.get_attributes(),
    }
    return user_data

@app.get("/sso/logout/")
async def sso_logout(request: Request):
    auth = prepare_saml_request(request)
    logout_url = auth.logout()
    return RedirectResponse(url=logout_url)

@app.post("/sso/sls/")
async def sls(request: Request):
    auth = prepare_saml_request(request)
    request_body = await request.body()
    auth.process_slo(request_body)
    return {"detail": "Logged out successfully"}

if __name__=="__main__":
    uvicorn.run(app,host="127.0.0.1",port=8080)