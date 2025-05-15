from flask import jsonify, Blueprint
import requests
from datetime import datetime, timedelta
import json
from extensions import db, limiter
from config import Config

api_bp = Blueprint('api', __name__)

# Simple global cache
RATES_CACHE = {
    'data': None,
    'currencies': None,
    'last_updated': None,
    'last_check': None
}

# Standardized error response helper
def error_response(code, message):
    return jsonify({
        "error": {
            "code": code,
            "message": message
        }
    }), code

# Function to fetch and save new currency data from the external API
def fetch_currency_data():
    try:
        response = requests.get(Config.CURRENCY_API_URL, timeout=10)  # Added timeout
        print(response)
        if response.status_code == 200:
            data = response.json()
            timestamp = datetime.now()
            
            # Get existing currency rates
            existing_currencies = db.execute("SELECT currency_code, rate FROM currencies")
            existing_rates = {curr["currency_code"]: curr["rate"] for curr in existing_currencies}
            
            # Check if any rates actually changed
            new_rates = {code.upper(): rate for code, rate in data["usd"].items()}
            changes_detected = False
            
            # Compare new rates with existing rates
            for currency_code, rate in new_rates.items():
                if (currency_code not in existing_rates) or (abs(existing_rates[currency_code] - rate) > 0.0000001):
                    changes_detected = True
                    break
            
            # If no changes detected, just update the cache timestamp and return
            if existing_rates and not changes_detected:
                print("No currency rate changes detected, skipping database update")
                RATES_CACHE['last_check'] = timestamp
                return True
            
            # If we reach here, changes were detected or no existing data
            print("Currency rate changes detected, updating database")
            
            # Create new API data entry
            db.execute("INSERT INTO api_data (base_currency, last_updated_at, json_data) VALUES (?, ?, ?)",
                      "USD", timestamp, json.dumps(data))
            
            # Get the last inserted API data ID
            api_data_id = db.execute("SELECT id FROM api_data ORDER BY id DESC LIMIT 1")[0]["id"]
            
            # Remove old API data entries (keep just the latest one)
            db.execute("DELETE FROM api_data WHERE id != ?", api_data_id)
            
            # Update existing currencies and add new ones
            for currency_code, rate in data["usd"].items():
                upper_code = currency_code.upper()
                # Update if exists, otherwise insert
                if upper_code in existing_rates:
                    db.execute("UPDATE currencies SET api_data_id = ?, rate = ? WHERE currency_code = ?",
                              api_data_id, rate, upper_code)
                else:
                    db.execute("INSERT INTO currencies (api_data_id, currency_code, rate) VALUES (?, ?, ?)",
                              api_data_id, upper_code, rate)
            
            # Clean up any currencies that no longer exist in the new data
            new_currency_codes = [code.upper() for code in data["usd"].keys()]
            for old_code in existing_rates.keys():
                if old_code not in new_currency_codes:
                    db.execute("DELETE FROM currencies WHERE currency_code = ?", old_code)

            # Update the cache
            currencies = db.execute("SELECT currency_code, rate FROM currencies")
            formatted_rates = {
                currency["currency_code"]: {
                    "code": currency["currency_code"],
                    "value": currency["rate"]
                }
                for currency in currencies
            }
            
            RATES_CACHE['data'] = formatted_rates
            RATES_CACHE['currencies'] = currencies
            RATES_CACHE['last_updated'] = timestamp
            RATES_CACHE['last_check'] = timestamp

            print(f"Currency data successfully updated at {timestamp}")
            return True
    except (requests.RequestException, json.JSONDecodeError, KeyError) as e:
        # Log the error properly
        print(f"Error fetching currency data: {str(e)}")
        return False
    
    return False

# Helper function to get the latest rates (from cache when possible)
def get_latest_rates():
    current_time = datetime.now()
    
    # If we have cached data and checked it recently (within 5 minutes), use it
    if (RATES_CACHE['data'] and RATES_CACHE['last_check'] and 
            (current_time - RATES_CACHE['last_check']).total_seconds() < 300):
        print("Using cached data without database check")
        return RATES_CACHE['data'], RATES_CACHE['currencies'], RATES_CACHE['last_updated'], False
    
    # We need to check if our cached data is still valid or if we need a fresh DB query
    print("Checking if cache needs refresh")
    RATES_CACHE['last_check'] = current_time
    
    # If we have cached data and it's from today, use it
    if (RATES_CACHE['data'] and RATES_CACHE['last_updated'] and 
            RATES_CACHE['last_updated'].date() == current_time.date()):
        print("Using cached data - same day update")
        return RATES_CACHE['data'], RATES_CACHE['currencies'], RATES_CACHE['last_updated'], False
    
    # Cache needs refresh - check the database first
    latest_data = db.execute("SELECT * FROM api_data ORDER BY last_updated_at DESC LIMIT 1")
    
    if not latest_data:
        print("No data in database")
        return None, None, None, False
        
    latest_data = latest_data[0]
    last_updated = datetime.fromisoformat(latest_data["last_updated_at"]) if isinstance(latest_data["last_updated_at"], str) else latest_data["last_updated_at"]
    
    # If database data is from today, load it into cache
    if last_updated.date() == current_time.date():
        currencies = db.execute("SELECT currency_code, rate FROM currencies")
        if not currencies:
            return None, None, None, False
            
        formatted_rates = {
            currency["currency_code"]: {
                "code": currency["currency_code"],
                "value": currency["rate"]
            }
            for currency in currencies
        }
        
        # Update cache with database data
        RATES_CACHE['data'] = formatted_rates
        RATES_CACHE['currencies'] = currencies
        RATES_CACHE['last_updated'] = last_updated
        
        print("Cache refreshed from database - same day data")
        return formatted_rates, currencies, last_updated, False
    
    # If we get here, database data is also outdated
    print("Both cache and database need refresh")
    return None, None, None, False

# Helper function to get fallback data when the external API fails
def get_fallback_data():
    # First try to get data from the database, even if it's old
    latest_data = db.execute("SELECT * FROM api_data ORDER BY last_updated_at DESC LIMIT 1")
    
    if latest_data:
        latest_data = latest_data[0]
        last_updated = datetime.fromisoformat(latest_data["last_updated_at"]) if isinstance(latest_data["last_updated_at"], str) else latest_data["last_updated_at"]
        
        currencies = db.execute("SELECT currency_code, rate FROM currencies")
        if currencies:
            formatted_rates = {
                currency["currency_code"]: {
                    "code": currency["currency_code"],
                    "value": currency["rate"]
                }
                for currency in currencies
            }
            
            # The data is stale but usable as fallback
            return formatted_rates, currencies, last_updated, True
    
    # If no data in database at all, we can't provide a fallback
    return None, None, None, False

# Route to fetch the latest currency rates
@api_bp.route('/latest_rates/<string:api_key>/<string:base_currency>', methods=['GET'])
@limiter.limit("30 per minute")
def latest_rates(api_key, base_currency='USD'):
    # Convert base_currency to uppercase
    base_currency = base_currency.upper()

    # Validate the API key
    user = db.execute("SELECT * FROM users WHERE api_key = ?", api_key)
    if not user:
        return error_response(401, "Invalid API key")

    # Get the latest rates (from cache or database)
    latest_data, currencies, last_updated_at, is_stale = get_latest_rates()

    # If no data or outdated data, fetch fresh data
    if latest_data is None:
        fetch_success = fetch_currency_data()
        if fetch_success:
            latest_data, currencies, last_updated_at, is_stale = get_latest_rates()
        else:
            # Try to get fallback data if external API fetch fails
            latest_data, currencies, last_updated_at, is_stale = get_fallback_data()
            
            # If no fallback data available either
            if latest_data is None:
                return error_response(503, "Failed to fetch currency data and no fallback data available")

    if currencies is None:
        return error_response(404, "No currency data found in the database")

    # Format the response
    rates = {currency["currency_code"]: currency["rate"] for currency in currencies}

    # Adjust rates based on the requested base currency
    if base_currency != 'USD':
        if base_currency not in rates:
            return error_response(400, f"Base currency '{base_currency}' not found")
        # Calculate conversion rates relative to the requested base currency
        base_rate = rates[base_currency]
        adjusted_rates = {currency_code: rate / base_rate for currency_code, rate in rates.items()}
        rates = adjusted_rates

    response_data = {
        "meta": {
            "base_currency": base_currency,
            "last_updated_at": last_updated_at
        },
        "data": rates
    }
    
    # Add warning if data is stale
    if is_stale:
        response_data["warning"] = {
            "message": "Using stale data as fallback. External API could not be reached.",
            "data_age": f"{(datetime.now() - last_updated_at).days} days old"
        }

    return jsonify(response_data)