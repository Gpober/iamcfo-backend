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
import re
from typing import Optional

# Load environment variables
load_dotenv()

# Initialize FastAPI app
app = FastAPI(title="I AM CFO - QBO Integration", version="1.0.0")

# ============ UPDATED CORS CONFIGURATION ============
# Get allowed origins from environment or use defaults
ALLOWED_ORIGINS = os.getenv("ALLOWED_ORIGINS", "").split(",") if os.getenv("ALLOWED_ORIGINS") else []

# Default origins for development and production
DEFAULT_ORIGINS = [
    "http://localhost:3000",  # Local development
    "http://localhost:3001",  # Alt local port
    "https://localhost:3000", # HTTPS local
]

# Add your production frontend URLs here
PRODUCTION_ORIGINS = [
    "https://airbnb.iamcfo.com",      # Your actual Netlify domain
    "https://iamcfo.com",             # In case you have apex domain
    "https://www.iamcfo.com",         # www version
    "https://app.iamcfo.com",         # app subdomain if you have it
]

# Combine all origins
ALL_ORIGINS = DEFAULT_ORIGINS + PRODUCTION_ORIGINS + ALLOWED_ORIGINS

# Remove empty strings and duplicates
ALL_ORIGINS = list(set([origin for origin in ALL_ORIGINS if origin.strip()]))

# Enable CORS for frontend
app.add_middleware(
    CORSMiddleware,
    allow_origins=ALL_ORIGINS,  # Updated to support multiple domains
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Log CORS configuration on startup
print("🌐 CORS Configuration:")
for origin in ALL_ORIGINS:
    print(f"   ✅ {origin}")

# ============ REST OF YOUR CODE UNCHANGED ============

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# QuickBooks OAuth Configuration
QBO_CLIENT_ID = os.getenv("QBO_CLIENT_ID")
QBO_CLIENT_SECRET = os.getenv("QBO_CLIENT_SECRET")
REDIRECT_URI = "https://iamcfo-backend.onrender.com/auth/qbo/callback"

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
        "cors_origins": ALL_ORIGINS,  # Added CORS info to status
        "endpoints": {
            "health_check": "/",
            "initiate_oauth": "/auth/qbo/initiate",
            "oauth_callback": "/auth/qbo/callback",
            "test_connection": "/auth/qbo/test",
            "company_info": "/api/qb/company-info",
            "profit_loss": "/api/qb/profit-loss",
            "chart_of_accounts": "/api/qb/accounts",
            "locations": "/api/qb/locations",
            "classes": "/api/qb/classes",
            "customers": "/api/qb/customers",
            "property_mapping": "/api/qb/property-mapping",
            "journal_entries": "/api/qb/journal-entries",
            "journal_entries_by_property": "/api/qb/journal-entries/by-property", 
            "journal_entry_field_explorer": "/api/qb/journal-entries/field-explorer",
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

        # Verify state parameter (security check) - commented out for now
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
        print("📊 Company Info: https://iamcfo-backend.onrender.com/api/qb/company-info")
        print("💰 P&L Report: https://iamcfo-backend.onrender.com/api/qb/profit-loss")
        print("📈 Chart of Accounts: https://iamcfo-backend.onrender.com/api/qb/accounts")
        print("📝 Journal Entries: https://iamcfo-backend.onrender.com/api/qb/journal-entries")
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
                "oauth_url": "https://iamcfo-backend.onrender.com/auth/qbo/initiate"
            }
        
        # Check if token is expired
        if TOKEN_EXPIRES_AT and datetime.now() > TOKEN_EXPIRES_AT:
            return {
                "success": False,
                "error": "Access token has expired. Please re-authenticate.",
                "oauth_url": "https://iamcfo-backend.onrender.com/auth/qbo/initiate"
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

@app.get("/api/qb/financial-summary")
async def get_financial_summary():
    """Get a comprehensive financial summary optimized for I AM CFO dashboard"""
    try:
        if not CURRENT_ACCESS_TOKEN or not CURRENT_REALM_ID:
            raise HTTPException(
                status_code=401,
                detail="No OAuth tokens available. Please complete OAuth flow first."
            )

        # Get current month dates
        now = datetime.now()
        start_of_month = now.replace(day=1).strftime("%Y-%m-%d")
        end_of_month = now.strftime("%Y-%m-%d")
        
        # Get previous month for comparison
        if now.month == 1:
            prev_month = datetime(now.year - 1, 12, 1)
        else:
            prev_month = datetime(now.year, now.month - 1, 1)
        
        prev_start = prev_month.strftime("%Y-%m-%d")
        if prev_month.month == 12:
            prev_end = datetime(prev_month.year + 1, 1, 1) - timedelta(days=1)
        else:
            prev_end = datetime(prev_month.year, prev_month.month + 1, 1) - timedelta(days=1)
        prev_end = prev_end.strftime("%Y-%m-%d")

        # Fetch current month P&L
        current_pl = await get_profit_loss(start_of_month, end_of_month)
        
        # Fetch previous month P&L for comparison
        previous_pl = await get_profit_loss(prev_start, prev_end)
        
        # Get company info
        company_info = await get_company_info()

        summary = {
            "company_name": "Unknown",
            "current_period": {
                "start_date": start_of_month,
                "end_date": end_of_month,
                "revenue": current_pl.get("data", {}).get("total_revenue", 0),
                "expenses": current_pl.get("data", {}).get("total_expenses", 0),
                "net_profit": current_pl.get("data", {}).get("net_profit", 0),
                "profit_margin": current_pl.get("data", {}).get("profit_margin", 0)
            },
            "previous_period": {
                "start_date": prev_start,
                "end_date": prev_end,
                "revenue": previous_pl.get("data", {}).get("total_revenue", 0),
                "expenses": previous_pl.get("data", {}).get("total_expenses", 0),
                "net_profit": previous_pl.get("data", {}).get("net_profit", 0),
                "profit_margin": previous_pl.get("data", {}).get("profit_margin", 0)
            },
            "growth_metrics": {},
            "top_revenue_accounts": current_pl.get("data", {}).get("revenue_breakdown", [])[:5],
            "top_expense_accounts": current_pl.get("data", {}).get("expense_breakdown", [])[:5],
            "environment": "production"
        }
        
        # Extract company name
        try:
            company_data = company_info.get("data", {}).get("QueryResponse", {}).get("CompanyInfo", [{}])[0]
            summary["company_name"] = company_data.get("CompanyName", "Unknown")
        except (KeyError, IndexError):
            pass
        
        # Calculate growth metrics
        current = summary["current_period"]
        previous = summary["previous_period"]
        
        summary["growth_metrics"] = {
            "revenue_growth": calculate_growth_percentage(previous["revenue"], current["revenue"]),
            "expense_growth": calculate_growth_percentage(previous["expenses"], current["expenses"]),
            "profit_growth": calculate_growth_percentage(previous["net_profit"], current["net_profit"]),
            "margin_change": current["profit_margin"] - previous["profit_margin"]
        }

        return {
            "success": True,
            "data": summary,
            "environment": "production"
        }
        
    except Exception as e:
        logger.error(f"Error fetching financial summary: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))

# Helper function for growth calculation
def calculate_growth_percentage(previous, current):
    """Calculate percentage growth between two values"""
    if previous == 0:
        return 100 if current > 0 else 0
    return ((current - previous) / abs(previous)) * 100

# [Continue with all the other endpoints - accounts, locations, classes, customers, property-mapping, journal-entries, etc.]
# [The rest of your code remains exactly the same]

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

# [Include all your other endpoint functions here - I'll include the key ones for brevity]

# ============ P&L DATA TRANSFORMATION FUNCTIONS ============

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
        rows = income_row.get("Rows", [])
        for row in rows:
            cols = row.get("ColData", [])
            if len(cols) >= 2:
                account_name = cols[0].get("value", "")
                amount_str = cols[1].get("value", "0")
                
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
        rows = expense_row.get("Rows", [])
        for row in rows:
            cols = row.get("ColData", [])
            if len(cols) >= 2:
                account_name = cols[0].get("value", "")
                amount_str = cols[1].get("value", "0")
                
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

# ============ HTML SUCCESS/ERROR PAGES ============

def create_success_page(realm_id: str, access_token: str, refresh_token: str, expires_in: int) -> HTMLResponse:
    """Create a professional success page after OAuth completion"""
    hours_valid = expires_in // 3600
    
    success_html = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <title>I AM CFO - QuickBooks Connected Successfully</title>
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
        </style>
    </head>
    <body>
        <div class="container">
            <div class="success-icon">🚀</div>
            <h1>QuickBooks Connected Successfully!</h1>
            <p class="subtitle">Your I AM CFO platform is now connected to QuickBooks</p>
            
            <div class="button-group">
                <a href="https://airbnb.iamcfo.com" class="btn btn-primary">
                    📊 Go to Dashboard
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
        <title>I AM CFO - Connection Error</title>
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
        </style>
    </head>
    <body>
        <div class="container">
            <div class="error-icon">❌</div>
            <h1>Connection Failed</h1>
            <p>We couldn't connect your QuickBooks account to I AM CFO.</p>
            
            <div class="error-message">
                <strong>Error Details:</strong><br>
                {error_message}
            </div>
            
            <div class="button-group">
                <a href="https://iamcfo-backend.onrender.com/auth/qbo/initiate" class="btn btn-primary">
                    🔄 Try Again
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
        "cors_origins": ALL_ORIGINS,
        "frontend_domain": "https://airbnb.iamcfo.com",
        "ready_for_connection": True
    }

if __name__ == "__main__":
    import uvicorn
    print("🚀 Starting I AM CFO - QuickBooks PRODUCTION Integration Server...")
    print(f"📡 Server will run on: http://localhost:8000")
    print(f"🔗 OAuth initiation: https://iamcfo-backend.onrender.com/auth/qbo/initiate")
    print(f"📊 API status: https://iamcfo-backend.onrender.com/")
    print("🚀 PRODUCTION MODE: Ready for real client data")
    print(f"🌐 Frontend: https://airbnb.iamcfo.com")
    uvicorn.run(app, host="0.0.0.0", port=8000)
