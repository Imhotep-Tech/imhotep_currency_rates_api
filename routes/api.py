from flask import jsonify, Blueprint
import requests
from datetime import datetime, timedelta
import json
from extensions import db
from config import Config

api_bp = Blueprint('api', __name__)

# Function to fetch and save new currency data from the external API
def fetch_currency_data():
    response = requests.get(Config.CURRENCY_API_URL)
    print(response)
    if response.status_code == 200:
        data = response.json()
        timestamp = datetime.now()
        
        db.execute("DELETE FROM api_data")

        # Insert the API data into the 'api_data' table
        db.execute("INSERT INTO api_data (base_currency, last_updated_at, json_data) VALUES (?, ?, ?)",
                   "USD", timestamp, json.dumps(data))

        # Get the last inserted API data ID
        api_data_id = db.execute("SELECT id FROM api_data ORDER BY id DESC LIMIT 1")[0]["id"]

        # Clear the currencies table to avoid duplicates
        db.execute("DELETE FROM currencies")

        # Save each currency rate in the 'currencies' table
        for currency_code, rate in data["usd"].items():
            db.execute("INSERT INTO currencies (api_data_id, currency_code, rate) VALUES (?, ?, ?)",
                       api_data_id, currency_code.upper(), rate)

        print(f"Currency data successfully fetched and saved at {timestamp}")
        return True
    return False

# Helper function to get the latest rates from the database
def get_latest_rates():
    # Get the most recent API data from the 'api_data' table
    latest_data = db.execute("SELECT * FROM api_data ORDER BY last_updated_at DESC LIMIT 1")

    if not latest_data:
        print("No data found in the 'api_data' table.")
        return None, None, None

    latest_data = latest_data[0]  # Get the first result

    # Fetch the related currency rates from the 'currencies' table
    currencies = db.execute("SELECT currency_code, rate FROM currencies")
    
    if not currencies:
        print(f"No currency data found for api_data_id {latest_data['id']}.")
        return latest_data, None, None
    
    formatted_rates = {
        currency["currency_code"]: {
            "code": currency["currency_code"],
            "value": currency["rate"]
        }
        for currency in currencies
    }

    return formatted_rates, currencies, latest_data["last_updated_at"]

# Route to fetch the latest currency rates
@api_bp.route('/latest_rates/<string:api_key>/<string:base_currency>', methods=['GET'])
def latest_rates(api_key, base_currency='USD'):
    # Convert base_currency to uppercase
    base_currency = base_currency.upper()

    # Validate the API key
    user = db.execute("SELECT * FROM users WHERE api_key = ?", api_key)
    if not user:
        return jsonify({"error": "Invalid API key"}), 401

    # Get the current time and the latest data from the database
    current_time = datetime.now()
    latest_data, currencies, last_updated_at = get_latest_rates()

    last_updated_at = datetime.fromisoformat(last_updated_at)

    # If no data exists or the last update was more than 24 hours ago, fetch new data
    if latest_data is None or last_updated_at.date() != current_time.date():
        fetch_success = fetch_currency_data()
        if fetch_success:
            latest_data, currencies, last_updated_at = get_latest_rates()
        else:
            return jsonify({"error": "Failed to fetch currency data from external API"}), 500

    if currencies is None:
        return jsonify({"error": "No currency data found in the database"}), 500

    # Format the response
    rates = {currency["currency_code"]: currency["rate"] for currency in currencies}

    # Adjust rates based on the requested base currency
    if base_currency != 'USD':
        if base_currency not in rates:
            return jsonify({"error": f"Base currency {base_currency} not found"}), 400
        # Calculate conversion rates relative to the requested base currency
        base_rate = rates[base_currency]
        adjusted_rates = {currency_code: rate / base_rate for currency_code, rate in rates.items()}
        rates = adjusted_rates

    return jsonify({
        "meta": {
            "base_currency": base_currency,
            "last_updated_at": last_updated_at
        },
        "data": rates
    })