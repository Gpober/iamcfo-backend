from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import RedirectResponse, HTMLResponse
from fastapi.middleware.cors import CORSMiddleware
import os
from dotenv import load_dotenv
import requests
import base64
import json
import logging
from urllib.parse import urlencode
import secrets
from datetime import datetime, timedelta

# Load environment variables
load_dotenv()

# Initialize FastAPI app
app = FastAPI(title="I AM CFO - QBO Integration", version="1.0.0")

# Enable CORS for frontend
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000"],  # Next.js default port
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# QuickBooks OAuth Configuration
QBO_CLIENT_ID = os.getenv("QBO_CLIENT_ID")
QBO_CLIENT_SECRET = os.getenv("QBO_CLIENT_SECRET")
REDIRECT_URI = "REDIRECT_URI = https://iamcfo-backend.onrender.com/auth/qbo/callback"

# QuickBooks endpoints - PRODUCTION MODE
QBO_AUTH_URL = "https://appcenter.intuit.com/connect/oauth2"
QBO_TOKEN_URL = "https://oauth.platform.intuit.com/oauth2/v1/tokens/bearer"
QBO_BASE_URL = "https://quickbooks.api.intuit.com"  # Production API

# Temporary storage for tokens (in production, use database)
# You'll replace these with actual values from your OAuth success
CURRENT_ACCESS_TOKEN = None
CURRENT_REALM_ID = None
CURRENT_REFRESH_TOKEN = None
TOKEN_EXPIRES_AT = None

# Check credentials on startup
if not QBO_CLIENT_ID or not QBO_CLIENT_SECRET:
    print("⚠️  WARNING: QBO_CLIENT_ID and QBO_CLIENT_SECRET not found in .env file")
    print("📝 Please create a .env file with your QuickBooks credentials")
    print("🔗 Get credentials at: https://developer.intuit.com")
else:
    print("✅ QuickBooks credentials loaded successfully")
    print(f"🔗 Client ID: {QBO_CLIENT_ID[:10]}...")
    print("🚀 Running in PRODUCTION mode")

# Store for OAuth state (in production, use Redis or database)
oauth_states = {}

@app.get("/")
async def root():
    """Health check endpoint with helpful information"""
    return {
        "message": "🎉 I AM CFO - QBO Integration API (PRODUCTION MODE)",
        "status": "running",
        "version": "1.0.0",
        "mode": "production",
        "qb_credentials_loaded": bool(QBO_CLIENT_ID and QBO_CLIENT_SECRET),
        "has_access_token": bool(CURRENT_ACCESS_TOKEN),
        "current_company": CURRENT_REALM_ID,
        "endpoints": {
            "health_check": "/",
            "initiate_oauth": "/auth/qbo/initiate",
            "oauth_callback": "/auth/qbo/callback",
            "test_connection": "/auth/qbo/test",
            "company_info": "/api/qb/company-info",
            "profit_loss": "/api/qb/profit-loss",
            "chart_of_accounts": "/api/qb/accounts",
            "test_qb_api": "/api/qb/test-connection"
        },
        "setup_required": not bool(QBO_CLIENT_ID and QBO_CLIENT_SECRET),
        "next_steps": [
            "Create .env file with QBO credentials" if not QBO_CLIENT_ID else "✅ Credentials loaded",
            "Set QuickBooks app to Production mode" if QBO_CLIENT_ID else "❌ Add credentials first",
            "Test OAuth flow at /auth/qbo/initiate" if not CURRENT_ACCESS_TOKEN else "✅ OAuth completed",
            "Test QB API endpoints" if CURRENT_ACCESS_TOKEN else "❌ Need OAuth tokens first",
            "Integrate with I AM CFO frontend"
        ]
    }

# ============ OAUTH ENDPOINTS ============

@app.get("/auth/qbo/initiate")
async def initiate_qbo_oauth():
    """
    Initiate QuickBooks OAuth flow - PRODUCTION MODE
    Redirects user to QuickBooks authorization page
    """
    try:
        # Check credentials
        if not QBO_CLIENT_ID or not QBO_CLIENT_SECRET:
            raise HTTPException(
                status_code=500,
                detail="QuickBooks credentials not configured. Please check your .env file."
            )

        # Generate state parameter for security (prevents CSRF attacks)
        state = secrets.token_urlsafe(32)
        oauth_states[state] = {
            "timestamp": datetime.now().isoformat(),
            "initiated": True
        }

        # Clean up old states (basic cleanup, in production use TTL)
        if len(oauth_states) > 100:
            # Keep only recent 50 states
            sorted_states = sorted(oauth_states.items(), key=lambda x: x[1]["timestamp"])
            oauth_states.clear()
            oauth_states.update(dict(sorted_states[-50:]))

        # OAuth parameters for QuickBooks PRODUCTION
        oauth_params = {
            "client_id": QBO_CLIENT_ID,
            "scope": "com.intuit.quickbooks.accounting",  # Access to accounting data
            "redirect_uri": REDIRECT_URI,
            "response_type": "code",
            "access_type": "offline",  # Get refresh token
            "state": state
        }

        # Build authorization URL
        auth_url = f"{QBO_AUTH_URL}?{urlencode(oauth_params)}"

        logger.info(f"🚀 Initiating PRODUCTION OAuth for client ID: {QBO_CLIENT_ID[:10]}...")
        logger.info(f"🔗 Redirect URI: {REDIRECT_URI}")
        logger.info(f"🔐 State: {state}")

        # Redirect user to QuickBooks authorization page
        return RedirectResponse(url=auth_url)

    except Exception as e:
        logger.error(f"Error initiating OAuth: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Failed to initiate OAuth: {str(e)}")

@app.get("/auth/qbo/callback")
async def qbo_oauth_callback(request: Request):
    """
    Handle QuickBooks OAuth callback - PRODUCTION MODE
    Exchange authorization code for access tokens
    """
    global CURRENT_ACCESS_TOKEN, CURRENT_REALM_ID, CURRENT_REFRESH_TOKEN, TOKEN_EXPIRES_AT
    
    try:
        # Get query parameters from callback
        query_params = dict(request.query_params)
        
        logger.info(f"🚀 PRODUCTION OAuth callback received")
        logger.info(f"📋 Parameters: {list(query_params.keys())}")

        # Check for OAuth errors
        if 'error' in query_params:
            error = query_params.get('error', 'Unknown error')
            error_description = query_params.get('error_description', 'No description provided')
            logger.error(f"OAuth error: {error} - {error_description}")
            return create_error_page(f"OAuth authorization failed: {error}")

        # Check for required parameters
        required_params = ['code', 'realmId']
        missing_params = [param for param in required_params if param not in query_params]
        if missing_params:
            error_msg = f"Missing required parameters: {', '.join(missing_params)}"
            logger.error(error_msg)
            return create_error_page(error_msg)

        # Extract parameters
        auth_code = query_params['code']
        realm_id = query_params['realmId']  # Company ID in QuickBooks
        state = query_params.get('state')

        # Verify state parameter (security check)
        #if state not in oauth_states:
         #   logger.error(f"Invalid state parameter: {state}")
          #  return create_error_page("Invalid state parameter - possible security issue")

        logger.info(f"🔄 Exchanging auth code for PRODUCTION tokens")
        logger.info(f"🏢 Realm ID (Production Company): {realm_id}")

        # Exchange authorization code for access token
        auth_header = base64.b64encode(f"{QBO_CLIENT_ID}:{QBO_CLIENT_SECRET}".encode()).decode()

        headers = {
            "Authorization": f"Basic {auth_header}",
            "Content-Type": "application/x-www-form-urlencoded"
        }

        data = {
            "grant_type": "authorization_code",
            "code": auth_code,
            "redirect_uri": REDIRECT_URI
        }

        # Make token exchange request
        logger.info("🌐 Making token exchange request to QuickBooks PRODUCTION...")
        response = requests.post(QBO_TOKEN_URL, headers=headers, data=data, timeout=30)

        if response.status_code != 200:
            error_msg = f"Token exchange failed with status {response.status_code}: {response.text}"
            logger.error(error_msg)
            return create_error_page("Failed to exchange authorization code for tokens")

        token_data = response.json()

        # Extract token information
        access_token = token_data.get('access_token')
        refresh_token = token_data.get('refresh_token')
        expires_in = token_data.get('expires_in', 3600)
        token_type = token_data.get('token_type', 'Bearer')

        # Validate token response
        if not access_token:
            logger.error("No access token received from QuickBooks")
            return create_error_page("Invalid token response from QuickBooks")

        # Store tokens globally (in production, store in database)
        CURRENT_ACCESS_TOKEN = access_token
        CURRENT_REALM_ID = realm_id
        CURRENT_REFRESH_TOKEN = refresh_token
        TOKEN_EXPIRES_AT = datetime.now() + timedelta(seconds=expires_in)

        # Success! Print tokens for debugging (in production, store securely)
        print("\n" + "="*70)
        print("🎉 QUICKBOOKS PRODUCTION OAUTH SUCCESS - I AM CFO")
        print("="*70)
        print(f"🚀 Mode: PRODUCTION")
        print(f"✅ Company ID (Realm): {realm_id}")
        print(f"🔑 Access Token: {access_token[:30]}...")
        print(f"🔄 Refresh Token: {refresh_token[:30] if refresh_token else 'N/A'}...")
        print(f"⏰ Expires in: {expires_in} seconds ({expires_in//3600} hours)")
        print(f"🏢 Token Type: {token_type}")
        print(f"🌐 API Base URL: {QBO_BASE_URL}")
        print("="*70)
        print("🚀 TOKENS STORED! You can now test QB API endpoints:")
        print("📊 Company Info: http://localhost:8000/api/qb/company-info")
        print("💰 P&L Report: http://localhost:8000/api/qb/profit-loss")
        print("📈 Chart of Accounts: http://localhost:8000/api/qb/accounts")
        print("="*70)

        # Clean up OAuth state
        if state in oauth_states:
            del oauth_states[state]

        # Return success page
        return create_success_page(realm_id, access_token, refresh_token, expires_in)

    except requests.exceptions.RequestException as e:
        logger.error(f"Network error during token exchange: {str(e)}")
        return create_error_page("Network error connecting to QuickBooks")
    except Exception as e:
        logger.error(f"Unexpected error in OAuth callback: {str(e)}")
        return create_error_page(f"Unexpected error: {str(e)}")

# ============ QUICKBOOKS DATA API ENDPOINTS ============

@app.get("/api/qb/test-connection")
async def test_qb_api_connection():
    """Test if QuickBooks API connection is working with current tokens"""
    try:
        if not CURRENT_ACCESS_TOKEN or not CURRENT_REALM_ID:
            return {
                "success": False,
                "error": "No OAuth tokens available. Please complete OAuth flow first.",
                "oauth_url": "http://localhost:8000/auth/qbo/initiate"
            }
        
        # Check if token is expired
        if TOKEN_EXPIRES_AT and datetime.now() > TOKEN_EXPIRES_AT:
            return {
                "success": False,
                "error": "Access token has expired. Please re-authenticate.",
                "oauth_url": "http://localhost:8000/auth/qbo/initiate"
            }

        headers = {
            "Authorization": f"Bearer {CURRENT_ACCESS_TOKEN}",
            "Accept": "application/json"
        }
        
        # Simple query to test connection
        url = f"{QBO_BASE_URL}/v3/company/{CURRENT_REALM_ID}/companyinfo/{CURRENT_REALM_ID}"
        response = requests.get(url, headers=headers, timeout=10)
        
        logger.info(f"🚀 QB API Test - Status: {response.status_code}")
        
        if response.status_code == 200:
            company_data = response.json()
            company_name = "Unknown"
            try:
                company_name = company_data["QueryResponse"]["CompanyInfo"][0]["CompanyName"]
            except (KeyError, IndexError):
                pass
                
            return {
                "success": True,
                "status_code": response.status_code,
                "message": "✅ QuickBooks API connection successful!",
                "company_name": company_name,
                "company_id": CURRENT_REALM_ID,
                "environment": "production",
                "token_valid": True
            }
        else:
            return {
                "success": False,
                "status_code": response.status_code,
                "error": "API request failed",
                "details": response.text[:200],
                "suggestion": "Token may be expired - try re-authenticating"
            }
        
    except Exception as e:
        logger.error(f"Error testing QB connection: {str(e)}")
        return {"success": False, "error": str(e)}

@app.get("/api/qb/company-info")
async def get_company_info():
    """Get basic company information from QuickBooks"""
    try:
        if not CURRENT_ACCESS_TOKEN or not CURRENT_REALM_ID:
            raise HTTPException(
                status_code=401,
                detail="No OAuth tokens available. Please complete OAuth flow first."
            )

        headers = {
            "Authorization": f"Bearer {CURRENT_ACCESS_TOKEN}",
            "Accept": "application/json"
        }
        
        url = f"{QBO_BASE_URL}/v3/company/{CURRENT_REALM_ID}/companyinfo/{CURRENT_REALM_ID}"
        
        logger.info(f"🏢 Fetching company info for realm: {CURRENT_REALM_ID}")
        response = requests.get(url, headers=headers, timeout=10)
        
        if response.status_code == 200:
            data = response.json()
            logger.info("✅ Company info retrieved successfully")
            return {
                "success": True,
                "data": data,
                "environment": "production"
            }
        else:
            logger.error(f"❌ Company info failed: {response.status_code}")
            raise HTTPException(
                status_code=response.status_code,
                detail=f"QuickBooks API Error: {response.text}"
            )
            
    except Exception as e:
        logger.error(f"Error fetching company info: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/qb/profit-loss")
async def get_profit_loss(start_date: str = None, end_date: str = None):
    """Fetch Profit & Loss report from QuickBooks"""
    try:
        if not CURRENT_ACCESS_TOKEN or not CURRENT_REALM_ID:
            raise HTTPException(
                status_code=401,
                detail="No OAuth tokens available. Please complete OAuth flow first."
            )
        
        # Default to current month if no dates provided
        if not start_date:
            start_date = datetime.now().replace(day=1).strftime("%Y-%m-%d")
        if not end_date:
            end_date = datetime.now().strftime("%Y-%m-%d")
        
        headers = {
            "Authorization": f"Bearer {CURRENT_ACCESS_TOKEN}",
            "Accept": "application/json"
        }
        
        # QuickBooks P&L Report API
        url = f"{QBO_BASE_URL}/v3/company/{CURRENT_REALM_ID}/reports/ProfitAndLoss"
        params = {
            "start_date": start_date,
            "end_date": end_date,
            "summarize_column_by": "Month"
        }
        
        logger.info(f"📊 Fetching P&L report: {start_date} to {end_date}")
        response = requests.get(url, headers=headers, params=params, timeout=15)
        
        if response.status_code == 200:
            data = response.json()
            logger.info("✅ P&L report retrieved successfully")
            
            # Transform QB data into I AM CFO format
            transformed_data = transform_pl_data(data)
            
            return {
                "success": True,
                "data": transformed_data,
                "raw_qb_data": data,  # Include raw data for debugging
                "period": f"{start_date} to {end_date}",
                "company_id": CURRENT_REALM_ID,
                "environment": "production"
            }
        else:
            logger.error(f"❌ P&L report failed: {response.status_code}")
            raise HTTPException(
                status_code=response.status_code,
                detail=f"QuickBooks P&L API Error: {response.text}"
            )
            
    except Exception as e:
        logger.error(f"Error fetching P&L: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/qb/accounts")
async def get_chart_of_accounts():
    """Get chart of accounts from QuickBooks"""
    try:
        if not CURRENT_ACCESS_TOKEN or not CURRENT_REALM_ID:
            raise HTTPException(
                status_code=401,
                detail="No OAuth tokens available. Please complete OAuth flow first."
            )

        headers = {
            "Authorization": f"Bearer {CURRENT_ACCESS_TOKEN}",
            "Accept": "application/json"
        }
        
        url = f"{QBO_BASE_URL}/v3/company/{CURRENT_REALM_ID}/query"
        params = {
            "query": "SELECT * FROM Account WHERE Active = true MAXRESULTS 100"
        }
        
        logger.info("📈 Fetching chart of accounts")
        response = requests.get(url, headers=headers, params=params, timeout=10)
        
        if response.status_code == 200:
            data = response.json()
            logger.info("✅ Chart of accounts retrieved successfully")
            
            # Extract and organize account data
            accounts = []
            if "QueryResponse" in data and "Account" in data["QueryResponse"]:
                for account in data["QueryResponse"]["Account"]:
                    accounts.append({
                        "id": account.get("Id"),
                        "name": account.get("Name"),
                        "type": account.get("AccountType"),
                        "subtype": account.get("AccountSubType"),
                        "balance": account.get("CurrentBalance", 0),
                        "active": account.get("Active", True)
                    })
            
            return {
                "success": True,
                "accounts": accounts,
                "total_accounts": len(accounts),
                "environment": "production",
                "raw_data": data
            }
        else:
            logger.error(f"❌ Chart of accounts failed: {response.status_code}")
            raise HTTPException(
                status_code=response.status_code,
                detail=f"QuickBooks Accounts API Error: {response.text}"
            )
            
    except Exception as e:
        logger.error(f"Error fetching accounts: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/qb/locations")
async def get_locations():
    """Get all locations from QuickBooks (key for property management)"""
    try:
        if not CURRENT_ACCESS_TOKEN or not CURRENT_REALM_ID:
            raise HTTPException(
                status_code=401,
                detail="No OAuth tokens available. Please complete OAuth flow first."
            )

        headers = {
            "Authorization": f"Bearer {CURRENT_ACCESS_TOKEN}",
            "Accept": "application/json"
        }
        
        url = f"{QBO_BASE_URL}/v3/company/{CURRENT_REALM_ID}/query"
        params = {
            "query": "SELECT * FROM Location WHERE Active = true MAXRESULTS 100"
        }
        
        logger.info("📍 Fetching locations")
        response = requests.get(url, headers=headers, params=params, timeout=10)
        
        if response.status_code == 200:
            data = response.json()
            logger.info("✅ Locations retrieved successfully")
            
            # Extract and organize location data
            locations = []
            if "QueryResponse" in data and "Location" in data["QueryResponse"]:
                for location in data["QueryResponse"]["Location"]:
                    locations.append({
                        "id": location.get("Id"),
                        "name": location.get("Name"),
                        "fully_qualified_name": location.get("FullyQualifiedName"),
                        "active": location.get("Active", True),
                        "sub_location": location.get("SubLocation", False),
                        "parent_ref": location.get("ParentRef", {}),
                        "description": location.get("Description", ""),
                        "create_time": location.get("CreateTime"),
                        "last_updated": location.get("LastUpdatedTime")
                    })
            
            return {
                "success": True,
                "locations": locations,
                "total_locations": len(locations),
                "environment": "production",
                "usage_tip": "Use these locations to track property-level transactions"
            }
        else:
            # Handle the case where Locations aren't supported/enabled
            error_data = response.json() if response.content else {}
            error_message = ""
            
            if "Fault" in error_data:
                fault = error_data["Fault"]
                if "Error" in fault and len(fault["Error"]) > 0:
                    error_message = fault["Error"][0].get("Message", "Unknown error")
            
            logger.warning(f"⚠️ Locations not available: {error_message}")
            
            # Return a helpful response instead of an error
            return {
                "success": False,
                "locations": [],
                "total_locations": 0,
                "environment": "production",
                "message": "Locations feature not enabled in this QuickBooks company",
                "error_details": error_message,
                "alternative_suggestion": "This company doesn't use Locations. Try Classes or Customers for property tracking instead.",
                "setup_help": "To use Locations: Go to QuickBooks → Settings → Company Settings → Advanced → Categories → Turn on Location tracking"
            }
            
    except Exception as e:
        logger.error(f"Error fetching locations: {str(e)}")
        return {
            "success": False,
            "locations": [],
            "total_locations": 0,
            "environment": "production",
            "message": "Locations not available in this QuickBooks setup",
            "error_details": str(e),
            "alternative_suggestion": "Try Classes or Customers for property tracking instead."
        }

@app.get("/api/qb/classes")
async def get_classes():
    """Get all classes from QuickBooks (alternative property tracking method)"""
    try:
        if not CURRENT_ACCESS_TOKEN or not CURRENT_REALM_ID:
            raise HTTPException(
                status_code=401,
                detail="No OAuth tokens available. Please complete OAuth flow first."
            )

        headers = {
            "Authorization": f"Bearer {CURRENT_ACCESS_TOKEN}",
            "Accept": "application/json"
        }
        
        url = f"{QBO_BASE_URL}/v3/company/{CURRENT_REALM_ID}/query"
        params = {
            "query": "SELECT * FROM Class WHERE Active = true MAXRESULTS 100"
        }
        
        logger.info("🏷️ Fetching classes")
        response = requests.get(url, headers=headers, params=params, timeout=10)
        
        if response.status_code == 200:
            data = response.json()
            logger.info("✅ Classes retrieved successfully")
            
            # Extract and organize class data
            classes = []
            if "QueryResponse" in data and "Class" in data["QueryResponse"]:
                for cls in data["QueryResponse"]["Class"]:
                    classes.append({
                        "id": cls.get("Id"),
                        "name": cls.get("Name"),
                        "fully_qualified_name": cls.get("FullyQualifiedName"),
                        "active": cls.get("Active", True),
                        "sub_class": cls.get("SubClass", False),
                        "parent_ref": cls.get("ParentRef", {}),
                        "description": cls.get("Description", ""),
                        "create_time": cls.get("CreateTime"),
                        "last_updated": cls.get("LastUpdatedTime")
                    })
            
            return {
                "success": True,
                "classes": classes,
                "total_classes": len(classes),
                "environment": "production",
                "usage_tip": "Use these classes to categorize transactions by property or department"
            }
        else:
            logger.error(f"❌ Classes failed: {response.status_code}")
            raise HTTPException(
                status_code=response.status_code,
                detail=f"QuickBooks Classes API Error: {response.text}"
            )
            
    except Exception as e:
        logger.error(f"Error fetching classes: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/qb/customers")
async def get_customers(limit: int = 100):
    """Get customers from QuickBooks (another way to track properties/tenants)"""
    try:
        if not CURRENT_ACCESS_TOKEN or not CURRENT_REALM_ID:
            raise HTTPException(
                status_code=401,
                detail="No OAuth tokens available. Please complete OAuth flow first."
            )

        headers = {
            "Authorization": f"Bearer {CURRENT_ACCESS_TOKEN}",
            "Accept": "application/json"
        }
        
        url = f"{QBO_BASE_URL}/v3/company/{CURRENT_REALM_ID}/query"
        params = {
            "query": f"SELECT * FROM Customer WHERE Active = true MAXRESULTS {limit}"
        }
        
        logger.info("👥 Fetching customers")
        response = requests.get(url, headers=headers, params=params, timeout=10)
        
        if response.status_code == 200:
            data = response.json()
            logger.info("✅ Customers retrieved successfully")
            
            # Extract and organize customer data
            customers = []
            if "QueryResponse" in data and "Customer" in data["QueryResponse"]:
                for customer in data["QueryResponse"]["Customer"]:
                    # Extract billing address
                    billing_addr = customer.get("BillAddr", {})
                    
                    customers.append({
                        "id": customer.get("Id"),
                        "name": customer.get("Name"),
                        "fully_qualified_name": customer.get("FullyQualifiedName"),
                        "display_name": customer.get("DisplayName"),
                        "active": customer.get("Active", True),
                        "taxable": customer.get("Taxable", False),
                        "balance": customer.get("Balance", 0),
                        "billing_address": {
                            "line1": billing_addr.get("Line1", ""),
                            "city": billing_addr.get("City", ""),
                            "state": billing_addr.get("CountrySubDivisionCode", ""),
                            "postal_code": billing_addr.get("PostalCode", ""),
                            "country": billing_addr.get("Country", "")
                        } if billing_addr else None,
                        "company_name": customer.get("CompanyName", ""),
                        "email": customer.get("PrimaryEmailAddr", {}).get("Address", ""),
                        "phone": customer.get("PrimaryPhone", {}).get("FreeFormNumber", ""),
                        "create_time": customer.get("CreateTime"),
                        "last_updated": customer.get("LastUpdatedTime")
                    })
            
            return {
                "success": True,
                "customers": customers,
                "total_customers": len(customers),
                "environment": "production",
                "usage_tip": "Use customers to track individual properties or tenants"
            }
        else:
            logger.error(f"❌ Customers failed: {response.status_code}")
            raise HTTPException(
                status_code=response.status_code,
                detail=f"QuickBooks Customers API Error: {response.text}"
            )
            
    except Exception as e:
        logger.error(f"Error fetching customers: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/qb/property-mapping")
async def get_property_mapping():
    """Get a comprehensive mapping of all potential property identifiers (Locations, Classes, Customers)"""
    try:
        if not CURRENT_ACCESS_TOKEN or not CURRENT_REALM_ID:
            raise HTTPException(
                status_code=401,
                detail="No OAuth tokens available. Please complete OAuth flow first."
            )

        logger.info("🗺️ Building comprehensive property mapping")
        
        # Fetch all three types of property identifiers (handle errors gracefully)
        try:
            locations_result = await get_locations()
        except Exception as e:
            logger.warning(f"Locations fetch failed: {e}")
            locations_result = {"locations": [], "success": False}
            
        try:
            classes_result = await get_classes()
        except Exception as e:
            logger.warning(f"Classes fetch failed: {e}")
            classes_result = {"classes": [], "success": False}
            
        try:
            customers_result = await get_customers()
        except Exception as e:
            logger.warning(f"Customers fetch failed: {e}")
            customers_result = {"customers": [], "success": False}
        
        # Build unified property mapping
        property_mapping = {
            "locations": {
                "available": locations_result.get("success", False),
                "count": len(locations_result.get("locations", [])),
                "items": locations_result.get("locations", []),
                "recommended_for": "Multi-location businesses, property management companies",
                "status": "✅ Available" if locations_result.get("success", False) else "❌ Not enabled in this QB company",
                "error_message": locations_result.get("error_details", "") if not locations_result.get("success", False) else ""
            },
            "classes": {
                "available": classes_result.get("success", False),
                "count": len(classes_result.get("classes", [])),
                "items": classes_result.get("classes", []),
                "recommended_for": "Departmental tracking, project-based accounting",
                "status": "✅ Available" if classes_result.get("success", False) else "❌ Not available",
                "error_message": classes_result.get("error_details", "") if not classes_result.get("success", False) else ""
            },
            "customers": {
                "available": customers_result.get("success", False),
                "count": len(customers_result.get("customers", [])),
                "items": customers_result.get("customers", []),
                "recommended_for": "Tenant tracking, individual property units",
                "status": "✅ Available" if customers_result.get("success", False) else "❌ Not available",
                "error_message": customers_result.get("error_details", "") if not customers_result.get("success", False) else ""
            },
            "summary": {
                "total_potential_properties": 0,
                "recommended_approach": "",
                "setup_suggestions": [],
                "available_methods": []
            }
        }
        
        # Calculate totals and provide recommendations
        total_locations = property_mapping["locations"]["count"]
        total_classes = property_mapping["classes"]["count"]
        total_customers = property_mapping["customers"]["count"]
        
        property_mapping["summary"]["total_potential_properties"] = total_locations + total_classes + total_customers
        
        # Track which methods are available
        available_methods = []
        if property_mapping["locations"]["available"]:
            available_methods.append("Locations")
        if property_mapping["classes"]["available"]:
            available_methods.append("Classes")
        if property_mapping["customers"]["available"]:
            available_methods.append("Customers")
            
        property_mapping["summary"]["available_methods"] = available_methods
        
        # Provide intelligent recommendations based on what's available
        suggestions = []
        
        if total_locations > 0:
            property_mapping["summary"]["recommended_approach"] = "Locations (Primary)"
            suggestions.append("✅ Use Locations for property tracking - ideal for real estate")
        elif total_classes > 0:
            property_mapping["summary"]["recommended_approach"] = "Classes (Primary)"
            suggestions.append("✅ Use Classes for property/department tracking")
        elif total_customers > 0:
            property_mapping["summary"]["recommended_approach"] = "Customers (Primary)"
            suggestions.append("✅ Use Customers for tenant or individual unit tracking")
        else:
            property_mapping["summary"]["recommended_approach"] = "Setup Required"
            suggestions.append("⚠️ No property identifiers found")
        
        # Add setup suggestions based on what's not available
        if not property_mapping["locations"]["available"]:
            suggestions.append("💡 To enable Locations: QB Settings → Company Settings → Advanced → Categories → Turn on Location tracking")
        
        if not property_mapping["classes"]["available"] and total_classes == 0:
            suggestions.append("💡 To use Classes: QB Settings → Company Settings → Advanced → Categories → Turn on Class tracking")
        
        if total_customers == 0:
            suggestions.append("💡 Consider adding Customers for tenant/unit tracking")
        
        property_mapping["summary"]["setup_suggestions"] = suggestions
        
        return {
            "success": True,
            "property_mapping": property_mapping,
            "environment": "production",
            "analysis": {
                "best_available_method": property_mapping["summary"]["recommended_approach"],
                "total_trackable_properties": property_mapping["summary"]["total_potential_properties"],
                "enabled_features": available_methods,
                "recommendations": suggestions[:3]  # Top 3 recommendations
            }
        }
        
    except Exception as e:
        logger.error(f"Error building property mapping: {str(e)}")
        return {
            "success": False,
            "error": str(e),
            "property_mapping": {
                "locations": {"available": False, "count": 0, "items": []},
                "classes": {"available": False, "count": 0, "items": []},
                "customers": {"available": False, "count": 0, "items": []},
                "summary": {
                    "recommended_approach": "Error occurred",
                    "setup_suggestions": ["Please check your QuickBooks connection and try again"]
                }
            }
        }

def transform_pl_data(qb_data):
    """Transform QuickBooks P&L data into I AM CFO dashboard format"""
    try:
        logger.info("🔄 Transforming P&L data for I AM CFO format")
        
        # Initialize transformed data structure
        transformed = {
            "total_revenue": 0,
            "total_expenses": 0,
            "net_profit": 0,
            "profit_margin": 0,
            "revenue_breakdown": [],
            "expense_breakdown": [],
            "property_level_data": [],
            "summary": {
                "period": "",
                "company_name": "",
                "currency": "USD"
            }
        }
        
        # QB P&L reports have a nested structure
        # We'll extract the key financial metrics
        try:
            report = qb_data.get("Report", {})
            header = report.get("Header", {})
            
            # Get report period
            if "ReportBasis" in header:
                transformed["summary"]["period"] = header.get("ReportBasis", "")
            
            # Process report rows to extract revenue and expenses
            rows = report.get("Rows", [])
            
            for row in rows:
                if row.get("group") == "Income":
                    # Process revenue/income items
                    process_income_section(row, transformed)
                elif row.get("group") == "Expenses":
                    # Process expense items
                    process_expense_section(row, transformed)
            
            # Calculate derived metrics
            transformed["net_profit"] = transformed["total_revenue"] - transformed["total_expenses"]
            if transformed["total_revenue"] > 0:
                transformed["profit_margin"] = (transformed["net_profit"] / transformed["total_revenue"]) * 100
            
            logger.info(f"✅ P&L transformation complete - Revenue: ${transformed['total_revenue']}, Expenses: ${transformed['total_expenses']}")
            
        except Exception as parse_error:
            logger.error(f"Error parsing QB P&L structure: {parse_error}")
            # Return basic structure even if parsing fails
            transformed["error"] = "Could not parse QB P&L structure"
        
        return transformed
        
    except Exception as e:
        logger.error(f"Error transforming P&L data: {e}")
        return {
            "error": f"Data transformation failed: {str(e)}",
            "total_revenue": 0,
            "total_expenses": 0,
            "net_profit": 0,
            "profit_margin": 0
        }

def process_income_section(income_row, transformed):
    """Process income/revenue section of P&L report"""
    try:
        # QB P&L structure varies, this is a basic implementation
        # You'll need to adjust based on actual QB response structure
        rows = income_row.get("Rows", [])
        for row in rows:
            cols = row.get("ColData", [])
            if len(cols) >= 2:
                account_name = cols[0].get("value", "")
                amount_str = cols[1].get("value", "0")
                
                # Convert amount to float
                try:
                    amount = float(amount_str.replace(",", "").replace("$", ""))
                    transformed["total_revenue"] += amount
                    transformed["revenue_breakdown"].append({
                        "account": account_name,
                        "amount": amount
                    })
                except (ValueError, AttributeError):
                    pass
    except Exception as e:
        logger.error(f"Error processing income section: {e}")

def process_expense_section(expense_row, transformed):
    """Process expense section of P&L report"""
    try:
        # QB P&L structure varies, this is a basic implementation
        rows = expense_row.get("Rows", [])
        for row in rows:
            cols = row.get("ColData", [])
            if len(cols) >= 2:
                account_name = cols[0].get("value", "")
                amount_str = cols[1].get("value", "0")
                
                # Convert amount to float
                try:
                    amount = float(amount_str.replace(",", "").replace("$", ""))
                    transformed["total_expenses"] += amount
                    transformed["expense_breakdown"].append({
                        "account": account_name,
                        "amount": amount
                    })
                except (ValueError, AttributeError):
                    pass
    except Exception as e:
        logger.error(f"Error processing expense section: {e}")

def create_success_page(realm_id: str, access_token: str, refresh_token: str, expires_in: int) -> HTMLResponse:
    """Create a professional success page after OAuth completion"""
    hours_valid = expires_in // 3600
    
    success_html = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <title>I AM CFO - QuickBooks PRODUCTION Connected Successfully</title>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <style>
            body {{ 
                font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
                margin: 0;
                padding: 20px;
                background: linear-gradient(135deg, #10b981 0%, #059669 100%);
                min-height: 100vh;
                display: flex;
                align-items: center;
                justify-content: center;
            }}
            .container {{
                background: white;
                border-radius: 16px;
                box-shadow: 0 20px 40px rgba(0,0,0,0.1);
                padding: 48px;
                max-width: 600px;
                width: 100%;
                text-align: center;
            }}
            .success-icon {{
                font-size: 64px;
                margin-bottom: 24px;
                animation: bounce 2s infinite;
            }}
            @keyframes bounce {{
                0%, 20%, 50%, 80%, 100% {{ transform: translateY(0); }}
                40% {{ transform: translateY(-10px); }}
                60% {{ transform: translateY(-5px); }}
            }}
            h1 {{
                color: #1f2937;
                font-size: 28px;
                margin-bottom: 16px;
                font-weight: 600;
            }}
            .subtitle {{
                color: #6b7280;
                font-size: 16px;
                margin-bottom: 32px;
            }}
            .production-notice {{
                background: #d1fae5;
                border: 1px solid #10b981;
                border-radius: 8px;
                padding: 16px;
                margin: 24px 0;
                color: #065f46;
                font-size: 14px;
            }}
            .info-grid {{
                display: grid;
                grid-template-columns: 1fr 1fr;
                gap: 16px;
                margin: 32px 0;
                text-align: left;
            }}
            .info-item {{
                background: #f8fafc;
                padding: 16px;
                border-radius: 8px;
                border: 1px solid #e2e8f0;
            }}
            .info-label {{
                font-size: 12px;
                font-weight: 600;
                color: #64748b;
                text-transform: uppercase;
                letter-spacing: 0.5px;
                margin-bottom: 4px;
            }}
            .info-value {{
                font-size: 14px;
                color: #1e293b;
                font-weight: 500;
            }}
            .status-badge {{
                display: inline-block;
                background: #10b981;
                color: white;
                padding: 4px 12px;
                border-radius: 20px;
                font-size: 12px;
                font-weight: 600;
            }}
            .next-steps {{
                background: #eff6ff;
                border: 1px solid #bfdbfe;
                border-radius: 12px;
                padding: 24px;
                margin: 32px 0;
                text-align: left;
            }}
            .next-steps h3 {{
                color: #1e40af;
                font-size: 16px;
                margin: 0 0 16px 0;
                font-weight: 600;
            }}
            .next-steps ul {{
                margin: 0;
                padding-left: 20px;
                color: #1e40af;
            }}
            .next-steps li {{
                margin-bottom: 8px;
                font-size: 14px;
            }}
            .api-endpoints {{
                background: #f0fdf4;
                border: 1px solid #bbf7d0;
                border-radius: 12px;
                padding: 20px;
                margin: 24px 0;
                text-align: left;
            }}
            .api-endpoints h4 {{
                color: #15803d;
                font-size: 14px;
                margin: 0 0 12px 0;
                font-weight: 600;
            }}
            .api-endpoint {{
                background: white;
                border: 1px solid #d1fae5;
                border-radius: 6px;
                padding: 8px 12px;
                margin: 8px 0;
                font-family: monospace;
                font-size: 12px;
            }}
            .api-endpoint a {{
                color: #059669;
                text-decoration: none;
            }}
            .api-endpoint a:hover {{
                text-decoration: underline;
            }}
            .developer-info {{
                background: #1f2937;
                border-radius: 8px;
                padding: 20px;
                margin: 24px 0;
                font-family: 'Monaco', 'Menlo', monospace;
                text-align: left;
            }}
            .developer-info h4 {{
                color: #10b981;
                font-size: 14px;
                margin: 0 0 12px 0;
                font-weight: 600;
            }}
            .developer-info .token-line {{
                color: #d1d5db;
                font-size: 12px;
                margin-bottom: 4px;
                word-break: break-all;
            }}
            .button-group {{
                display: flex;
                gap: 16px;
                justify-content: center;
                margin-top: 32px;
            }}
            .btn {{
                padding: 12px 24px;
                border-radius: 8px;
                text-decoration: none;
                font-weight: 600;
                font-size: 14px;
                transition: all 0.2s;
                border: none;
                cursor: pointer;
            }}
            .btn-primary {{
                background: #3b82f6;
                color: white;
            }}
            .btn-primary:hover {{
                background: #2563eb;
                transform: translateY(-1px);
            }}
            .btn-secondary {{
                background: #f1f5f9;
                color: #475569;
                border: 1px solid #e2e8f0;
            }}
            .btn-secondary:hover {{
                background: #e2e8f0;
            }}
            @media (max-width: 640px) {{
                .container {{ padding: 24px; }}
                .info-grid {{ grid-template-columns: 1fr; }}
                .button-group {{ flex-direction: column; }}
            }}
        </style>
    </head>
    <body>
        <div class="container">
            <div class="success-icon">🚀</div>
            <h1>QuickBooks PRODUCTION Connected!</h1>
            <p class="subtitle">Your I AM CFO platform is now connected to real QuickBooks data</p>
            
            <div class="production-notice">
                <strong>🚀 PRODUCTION MODE:</strong> You're now connected to real client data! 
                You can access live financial information and build real property-level insights.
            </div>
            
            <div class="info-grid">
                <div class="info-item">
                    <div class="info-label">Company ID</div>
                    <div class="info-value">{realm_id}</div>
                </div>
                <div class="info-item">
                    <div class="info-label">Connection Status</div>
                    <div class="info-value"><span class="status-badge">Production Active</span></div>
                </div>
                <div class="info-item">
                    <div class="info-label">Access Level</div>
                    <div class="info-value">Full Production Data</div>
                </div>
                <div class="info-item">
                    <div class="info-label">Token Valid For</div>
                    <div class="info-value">{hours_valid} hours</div>
                </div>
            </div>
            
            <div class="api-endpoints">
                <h4>🚀 Test QuickBooks API Endpoints (LIVE DATA):</h4>
                <div class="api-endpoint">
                    <a href="http://localhost:8000/api/qb/test-connection" target="_blank">
                        📡 Test Connection
                    </a>
                </div>
                <div class="api-endpoint">
                    <a href="http://localhost:8000/api/qb/company-info" target="_blank">
                        🏢 Company Information
                    </a>
                </div>
                <div class="api-endpoint">
                    <a href="http://localhost:8000/api/qb/profit-loss" target="_blank">
                        💰 Profit & Loss Report
                    </a>
                </div>
                <div class="api-endpoint">
                    <a href="http://localhost:8000/api/qb/accounts" target="_blank">
                        📈 Chart of Accounts
                    </a>
                </div>
                <div class="api-endpoint">
                    <a href="http://localhost:8000/api/qb/locations" target="_blank">
                        📍 Locations (Properties)
                    </a>
                </div>
                <div class="api-endpoint">
                    <a href="http://localhost:8000/api/qb/classes" target="_blank">
                        🏷️ Classes (Departments)
                    </a>
                </div>
                <div class="api-endpoint">
                    <a href="http://localhost:8000/api/qb/customers" target="_blank">
                        👥 Customers (Tenants)
                    </a>
                </div>
                <div class="api-endpoint">
                    <a href="http://localhost:8000/api/qb/property-mapping" target="_blank">
                        🗺️ Property Mapping Analysis
                    </a>
                </div>
            </div>
            
            <div class="next-steps">
                <h3>🎉 What happens next:</h3>
                <ul>
                    <li>✅ Connected to REAL QuickBooks data!</li>
                    <li>📊 Access live financial reports and property insights</li>
                    <li>🏠 Build property-level profitability analysis</li>
                    <li>💼 Ready for production client onboarding</li>
                </ul>
            </div>
            
            <div class="developer-info">
                <h4>🔧 Developer Information:</h4>
                <div class="token-line">Environment: PRODUCTION</div>
                <div class="token-line">Realm ID: {realm_id}</div>
                <div class="token-line">Access Token: {access_token[:40]}...</div>
                <div class="token-line">Refresh Token: {refresh_token[:40] if refresh_token else 'N/A'}...</div>
                <div class="token-line">Expires: {expires_in} seconds ({hours_valid} hours)</div>
                <div class="token-line">API URL: {QBO_BASE_URL}</div>
            </div>
            
            <div class="button-group">
                <a href="http://localhost:3000/dashboard" class="btn btn-primary">
                    📊 View I AM CFO Dashboard
                </a>
                <a href="http://localhost:8000/" class="btn btn-secondary">
                    🔧 API Status
                </a>
            </div>
        </div>
    </body>
    </html>
    """
    
    return HTMLResponse(content=success_html)

def create_error_page(error_message: str) -> HTMLResponse:
    """Create a professional error page for OAuth failures"""
    error_html = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <title>I AM CFO - PRODUCTION Connection Error</title>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <style>
            body {{ 
                font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
                margin: 0;
                padding: 20px;
                background: linear-gradient(135deg, #ef4444 0%, #dc2626 100%);
                min-height: 100vh;
                display: flex;
                align-items: center;
                justify-content: center;
            }}
            .container {{
                background: white;
                border-radius: 16px;
                box-shadow: 0 20px 40px rgba(0,0,0,0.1);
                padding: 48px;
                max-width: 500px;
                width: 100%;
                text-align: center;
            }}
            .error-icon {{
                font-size: 64px;
                margin-bottom: 24px;
                animation: shake 0.5s ease-in-out;
            }}
            @keyframes shake {{
                0%, 100% {{ transform: translateX(0); }}
                25% {{ transform: translateX(-5px); }}
                75% {{ transform: translateX(5px); }}
            }}
            h1 {{
                color: #1f2937;
                font-size: 24px;
                margin-bottom: 16px;
                font-weight: 600;
            }}
            .error-message {{
                background: #fef2f2;
                border: 1px solid #fecaca;
                border-radius: 8px;
                padding: 16px;
                margin: 24px 0;
                color: #991b1b;
                font-size: 14px;
                text-align: left;
            }}
            .help-section {{
                background: #f8fafc;
                border-radius: 8px;
                padding: 20px;
                margin: 24px 0;
                text-align: left;
            }}
            .help-section h3 {{
                color: #1e293b;
                font-size: 16px;
                margin: 0 0 12px 0;
            }}
            .help-section ul {{
                margin: 0;
                padding-left: 20px;
                color: #475569;
            }}
            .help-section li {{
                margin-bottom: 6px;
                font-size: 14px;
            }}
            .button-group {{
                display: flex;
                gap: 16px;
                justify-content: center;
                margin-top: 32px;
            }}
            .btn {{
                padding: 12px 24px;
                border-radius: 8px;
                text-decoration: none;
                font-weight: 600;
                font-size: 14px;
                transition: all 0.2s;
            }}
            .btn-primary {{
                background: #3b82f6;
                color: white;
            }}
            .btn-primary:hover {{
                background: #2563eb;
            }}
            .btn-secondary {{
                background: #f1f5f9;
                color: #475569;
                border: 1px solid #e2e8f0;
            }}
            .btn-secondary:hover {{
                background: #e2e8f0;
            }}
            @media (max-width: 640px) {{
                .container {{ padding: 24px; }}
                .button-group {{ flex-direction: column; }}
            }}
        </style>
    </head>
    <body>
        <div class="container">
            <div class="error-icon">❌</div>
            <h1>PRODUCTION Connection Failed</h1>
            <p>We couldn't connect your QuickBooks Production account to I AM CFO.</p>
            
            <div class="error-message">
                <strong>Error Details:</strong><br>
                {error_message}
            </div>
            
            <div class="help-section">
                <h3>💡 Production Setup Checklist:</h3>
                <ul>
                    <li>✅ QuickBooks app is in Production mode</li>
                    <li>✅ Redirect URI: https://your-ngrok-url.ngrok.io/auth/qbo/callback</li>
                    <li>✅ Using production credentials in .env file</li>
                    <li>✅ Try using a different browser or incognito mode</li>
                </ul>
            </div>
            
            <div class="button-group">
                <a href="http://localhost:8000/auth/qbo/initiate" class="btn btn-primary">
                    🔄 Try Again
                </a>
                <a href="http://localhost:8000/" class="btn btn-secondary">
                    🔧 API Status
                </a>
            </div>
        </div>
    </body>
    </html>
    """
    
    return HTMLResponse(content=error_html)

@app.get("/auth/qbo/test")
async def test_qbo_connection():
    """Test endpoint to verify everything is working"""
    return {
        "message": "🚀 I AM CFO QBO PRODUCTION OAuth API is ready!",
        "status": "operational",
        "mode": "production",
        "credentials_loaded": bool(QBO_CLIENT_ID and QBO_CLIENT_SECRET),
        "has_tokens": bool(CURRENT_ACCESS_TOKEN),
        "endpoints": {
            "start_oauth": "/auth/qbo/initiate",
            "callback_url": REDIRECT_URI,
            "test_api": "/api/qb/test-connection",
            "company_info": "/api/qb/company-info",
            "profit_loss": "/api/qb/profit-loss",
            "accounts": "/api/qb/accounts"
        },
        "ready_for_testing": bool(QBO_CLIENT_ID and QBO_CLIENT_SECRET),
        "next_steps": [
            "✅ Get QuickBooks developer credentials" if QBO_CLIENT_ID else "❌ Add QBO_CLIENT_ID to .env",
            "✅ Set QB app to Production mode" if QBO_CLIENT_ID else "❌ Add QBO_CLIENT_SECRET to .env",
            "✅ Add ngrok redirect URI in QB developer portal",
            "✅ Test OAuth flow at /auth/qbo/initiate" if not CURRENT_ACCESS_TOKEN else "✅ OAuth completed",
            "✅ Test QB API endpoints" if CURRENT_ACCESS_TOKEN else "❌ Complete OAuth first",
            "✅ Store tokens in database",
            "✅ Fetch PRODUCTION P&L data" if CURRENT_ACCESS_TOKEN else "❌ Get tokens first"
        ]
    }

if __name__ == "__main__":
    import uvicorn
    print("🚀 Starting I AM CFO - QuickBooks PRODUCTION Integration Server...")
    print(f"📡 Server will run on: http://localhost:8000")
    print(f"🔗 OAuth initiation: http://localhost:8000/auth/qbo/initiate")
    print(f"📊 API status: http://localhost:8000/")
    print("🚀 PRODUCTION MODE: Ready for real client data")
    print("\n🚀 API ENDPOINTS:")
    print("📡 Test Connection: http://localhost:8000/api/qb/test-connection")
    print("🏢 Company Info: http://localhost:8000/api/qb/company-info")
    print("💰 P&L Report: http://localhost:8000/api/qb/profit-loss")
    print("📈 Chart of Accounts: http://localhost:8000/api/qb/accounts")
    uvicorn.run(app, host="0.0.0.0", port=8000)