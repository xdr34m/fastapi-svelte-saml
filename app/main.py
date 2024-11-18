from fastapi import FastAPI, Request, Form, HTTPException
from typing import Optional
from starlette.responses import RedirectResponse, HTMLResponse
import os,base64,uvicorn
from onelogin.saml2.auth import OneLogin_Saml2_Auth
from onelogin.saml2.settings import OneLogin_Saml2_Settings
from onelogin.saml2.utils import OneLogin_Saml2_Utils
from xml.etree import ElementTree as ET

app = FastAPI(root_path="/api")

# Helper function to prepare SAML request
async def prepare_saml_request(request: Request):
    print(request.url.path)
    form = {
        "https": "on" if request.url.scheme == "https" else "off",
        "http_host": request.client.host,
        "script_name": request.scope.get("root_path", ""),
        "server_port": request.url.port,
        "path_info": request.url.path,
        "get_data": request.query_params,
        "post_data": await request.form(),  # Await the form data here
    }
    return OneLogin_Saml2_Auth(form, custom_base_path=os.path.join(os.getcwd(), "app", "saml"))

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
    auth = await prepare_saml_request(request)
    login_url = auth.login()
    return RedirectResponse(url=login_url)

@app.post("/sso/acs/")
async def acs(request: Request):
    # Prepare the SAML request
    saml_auth = await prepare_saml_request(request)

    # Get the raw SAMLResponse from the request form data
    form_data = await request.form()
    saml_response = form_data.get("SAMLResponse")

    # Check if SAMLResponse is missing
    if not saml_response:
        return {"error": "SAMLResponse parameter missing in the request"}

    # Print the raw SAMLResponse for debugging
    print("Raw SAML Response (Base64):", saml_response)

    # Decode the base64-encoded SAMLResponse to inspect it
    decoded_response = base64.b64decode(saml_response).decode('utf-8')
    print("Decoded SAML Response (XML):", decoded_response)



    
    # Process the SAML response
    try:
        saml_auth.process_response()
    except Exception as e:
        return {"error": f"SAML processing error: {str(e)}"}

    # Parse the XML for attributes
    root = ET.fromstring(decoded_response)

    # Define the SAML namespace
    saml_ns = {'saml': 'urn:oasis:names:tc:SAML:2.0:assertion'}

    # Extract attributes
    attributes = {}
    for attribute in root.findall(".//saml:Attribute", namespaces=saml_ns):
        attr_name = attribute.attrib.get("Name")
        attr_values = [
            value.text for value in attribute.findall(".//saml:AttributeValue", namespaces=saml_ns)
        ]
        attributes[attr_name] = attr_values[0] if len(attr_values) == 1 else attr_values
    print(attributes)
    # Get the user attributes from the SAML response
    user_attributes = saml_auth.get_attributes()

    # Check if attributes are found
    if not user_attributes:
        return {"error": "No attributes found in the SAML response"}

    # Extract specific attributes, handle cases where they might be missing
    login_name = user_attributes.get("login_name", [None])[0]
    email = user_attributes.get("email", [None])[0]
    first_name = user_attributes.get("firstName", [None])[0]
    last_name = user_attributes.get("lastName", [None])[0]

    # Prepare the response
    response_data = {
        "message": "SAML response processed successfully",
        "login_name": login_name,
        "email": email,
        "first_name": first_name,
        "last_name": last_name,
        "user_attributes": user_attributes  # Include all attributes for debugging
    }

    return response_data
@app.get("/sso/logout/")
async def sso_logout(request: Request):
    auth = await prepare_saml_request(request)
    logout_url = auth.logout()
    return RedirectResponse(url=logout_url)

@app.post("/sso/sls/")
async def sls(request: Request):
    auth = await prepare_saml_request(request)
    request_body = await request.body()
    auth.process_slo(request_body)
    return {"detail": "Logged out successfully"}

if __name__=="__main__":
    uvicorn.run(app,host="127.0.0.1",port=8080)