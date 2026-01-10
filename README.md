# Imhotep Exchange Rates API

A free, production-ready REST API for retrieving real-time foreign exchange rates and performing currency conversions. Perfect for developers building e-commerce platforms, financial applications, travel services, and any application requiring currency data.

[![GitHub](https://img.shields.io/badge/GitHub-Repository-blue?logo=github)](https://github.com/Imhotep-Tech/imhotep_currency_rates_api)
[![Version](https://img.shields.io/badge/Version-3.1-blue)](https://imhotepexchangeratesapi.pythonanywhere.com/version)
[![License](https://img.shields.io/badge/License-MIT-green)](LICENSE)

## Table of Contents

- [Overview](#overview)
- [Features](#features)
- [Base URL](#base-url)
- [Authentication](#authentication)
- [Getting Started](#getting-started)
- [API Endpoints](#api-endpoints)
  - [Get Latest Exchange Rates](#get-latest-exchange-rates)
  - [Convert Currency Amount](#convert-currency-amount)
- [Response Formats](#response-formats)
- [Error Handling](#error-handling)
- [Rate Limiting](#rate-limiting)
- [Supported Currencies](#supported-currencies)
- [Code Examples](#code-examples)
- [Best Practices](#best-practices)

## Overview

The Imhotep Exchange Rates API provides access to real-time foreign exchange rates for major world currencies. All rates are based on USD and can be converted to any supported base currency. The API features intelligent caching, automatic fallback to cached data when external services are unavailable, and comprehensive error handling.

## Features

- **Completely Free**: No hidden costs, subscription fees, or credit card required
- **Real-time Exchange Rates**: Get the latest currency rates updated daily
- **Flexible Base Currency**: Request rates relative to any supported currency
- **Currency Conversion**: Convert specific amounts between any two currencies
- **Secure API Access**: Unique API key per user for authenticated requests
- **Intelligent Caching**: Fast responses with automatic cache management
- **Graceful Fallbacks**: Automatic fallback to cached data when external API is unavailable
- **Rate Limiting**: 30 requests per minute per API key
- **RESTful Design**: Simple, intuitive REST API following industry standards

## Base URL

```
https://imhotepexchangeratesapi.pythonanywhere.com
```

All API endpoints are relative to this base URL.

## Authentication

All API requests require authentication using an API key. The API key must be included as a path parameter in the request URL.

**Important Security Notes:**
- Keep your API key confidential and never expose it in client-side code
- Do not commit API keys to version control systems
- Make API requests from your backend server, not from client-side JavaScript
- If your API key is compromised, contact support immediately

## Getting Started

### Step 1: Sign Up and Get Your API Key

1. Visit the [homepage](https://imhotepexchangeratesapi.pythonanywhere.com) and register for a free account
2. Upon registration, you'll receive a unique API key
3. Your API key will be displayed in your dashboard after logging in

### Step 2: Make Your First Request

Try fetching the latest exchange rates with USD as the base currency:

```bash
curl https://imhotepexchangeratesapi.pythonanywhere.com/latest_rates/YOUR_API_KEY/USD
```

Replace `YOUR_API_KEY` with your actual API key.

## API Endpoints

### Get Latest Exchange Rates

Retrieve the latest exchange rates for all supported currencies relative to a specified base currency.

**Endpoint:** `/latest_rates/{api_key}/{base_currency}`

**Method:** `GET`

**Path Parameters:**

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `api_key` | string | Yes | Your unique API key |
| `base_currency` | string | Yes | ISO 4217 currency code (e.g., USD, EUR, GBP, JPY). Case-insensitive. |

**Example Request:**

```bash
GET https://imhotepexchangeratesapi.pythonanywhere.com/latest_rates/YOUR_API_KEY/USD
```

**Success Response:**

**Status Code:** `200 OK`

```json
{
  "meta": {
    "base_currency": "USD",
    "last_updated_at": "2024-10-25T15:00:00"
  },
  "data": {
    "EUR": 0.85,
    "GBP": 0.74,
    "JPY": 110.25,
    "CAD": 1.35,
    "AUD": 1.52,
    "CHF": 0.92,
    "CNY": 7.25,
    "INR": 83.12,
    "BRL": 5.05,
    "MXN": 18.50
  }
}
```

**Response with Stale Data Warning:**

When the external currency API is unavailable, the service returns cached data with a warning:

```json
{
  "meta": {
    "base_currency": "USD",
    "last_updated_at": "2024-10-22T18:00:00"
  },
  "warning": {
    "message": "Using stale data as fallback. External API could not be reached.",
    "data_age": "2 days old"
  },
  "data": {
    "EUR": 0.85,
    "GBP": 0.74,
    "JPY": 110.25
  }
}
```

**Example with Different Base Currency:**

```bash
GET https://imhotepexchangeratesapi.pythonanywhere.com/latest_rates/YOUR_API_KEY/EUR
```

Response will show all rates relative to EUR:

```json
{
  "meta": {
    "base_currency": "EUR",
    "last_updated_at": "2024-10-25T15:00:00"
  },
  "data": {
    "USD": 1.1765,
    "GBP": 0.8706,
    "JPY": 129.71,
    "CAD": 1.5882
  }
}
```

### Convert Currency Amount

Convert a specific amount from one currency to another using the latest exchange rates.

**Endpoint:** `/convert/latest_rates/{api_key}/{base_currency}/{target_currency}/{amount}`

**Method:** `GET`

**Path Parameters:**

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `api_key` | string | Yes | Your unique API key |
| `base_currency` | string | Yes | ISO 4217 currency code to convert from (e.g., USD). Case-insensitive. |
| `target_currency` | string | Yes | ISO 4217 currency code to convert to (e.g., EUR). Case-insensitive. |
| `amount` | integer | Yes | The amount to convert (must be a positive integer) |

**Example Request:**

```bash
GET https://imhotepexchangeratesapi.pythonanywhere.com/convert/latest_rates/YOUR_API_KEY/USD/EUR/100
```

**Success Response:**

**Status Code:** `200 OK`

```json
{
  "meta": {
    "base_currency": "USD",
    "target_currency": "EUR",
    "amount": 100,
    "last_updated_at": "2024-10-25T15:00:00"
  },
  "data": {
    "conversion_rate": 0.85,
    "converted_amount": 85.0
  }
}
```

**Response with Stale Data Warning:**

```json
{
  "meta": {
    "base_currency": "USD",
    "target_currency": "EUR",
    "amount": 100,
    "last_updated_at": "2024-10-22T18:00:00"
  },
  "warning": {
    "message": "Using stale data as fallback. External API could not be reached.",
    "data_age": "2 days old"
  },
  "data": {
    "conversion_rate": 0.85,
    "converted_amount": 85.0
  }
}
```

## Response Formats

### Success Response Structure

All successful API responses follow this structure:

```json
{
  "meta": {
    "base_currency": "string",
    "last_updated_at": "ISO 8601 datetime",
    // Additional meta fields for conversion endpoint:
    "target_currency": "string",
    "amount": number
  },
  "data": {
    // Response data (varies by endpoint)
  },
  "warning": {
    // Optional: Only present when using stale fallback data
    "message": "string",
    "data_age": "string"
  }
}
```

### Field Descriptions

- **`meta.base_currency`**: The base currency used for the exchange rates
- **`meta.target_currency`**: (Conversion endpoint only) The target currency for conversion
- **`meta.amount`**: (Conversion endpoint only) The original amount to convert
- **`meta.last_updated_at`**: ISO 8601 formatted timestamp of when the exchange rates were last updated
- **`data`**: The actual response data (rates object or conversion result)
- **`warning`**: (Optional) Present when using cached fallback data due to external API unavailability

## Error Handling

The API uses standard HTTP status codes and returns structured error responses to help with debugging.

### Error Response Format

All error responses follow this structure:

```json
{
  "error": {
    "code": 401,
    "message": "Invalid API key"
  }
}
```

### HTTP Status Codes

| Status Code | Error Type | Description | Common Causes |
|-------------|------------|-------------|----------------|
| `400` | Bad Request | The request was malformed or contains invalid parameters | Invalid currency code, missing required parameters |
| `401` | Unauthorized | Missing or invalid API key | API key not provided, incorrect API key |
| `404` | Not Found | The requested resource could not be found | Currency code not supported, no data available |
| `429` | Too Many Requests | Rate limit exceeded | More than 30 requests per minute |
| `500` | Internal Server Error | An unexpected error occurred on the server | Server-side issue |
| `503` | Service Unavailable | External currency API is unavailable and no fallback data exists | External API down, no cached data available |

### Common Error Examples

**Invalid API Key:**

```json
{
  "error": {
    "code": 401,
    "message": "Invalid API key"
  }
}
```

**Currency Not Found:**

```json
{
  "error": {
    "code": 400,
    "message": "Base currency 'XYZ' not found"
  }
}
```

**Rate Limit Exceeded:**

```json
{
  "error": {
    "code": 429,
    "message": "429 Too Many Requests: 30 per 1 minute"
  }
}
```

**Service Unavailable:**

```json
{
  "error": {
    "code": 503,
    "message": "Failed to fetch currency data and no fallback data available"
  }
}
```

## Rate Limiting

The API enforces rate limiting to ensure fair usage and system stability.

- **Limit:** 30 requests per minute per API key
- **Window:** 1 minute rolling window
- **Exceeding Limit:** Returns `429 Too Many Requests` status code

**Best Practices:**
- Implement request queuing or exponential backoff in your application
- Cache API responses on your end when possible
- Monitor your request rate to stay within limits
- Consider batching operations when possible

## Supported Currencies

Supported currency codes are the **keys returned under** `data` from:

```
/latest_rates/{api_key}/{base_currency}
```

Because the upstream provider can evolve, the most reliable way to get the current supported list is to generate it from the API response.

### Copy/paste (JSON array)

```bash
curl -s "https://imhotepexchangeratesapi.pythonanywhere.com/latest_rates/YOUR_API_KEY/USD" \
  | jq -c '.data | keys | map(ascii_upcase) | unique | sort'
```

### Copy/paste (one code per line)

```bash
curl -s "https://imhotepexchangeratesapi.pythonanywhere.com/latest_rates/YOUR_API_KEY/USD" \
  | jq -r '.data | keys | map(ascii_upcase) | unique | sort[]'
```

### Programmatic extraction

**JavaScript**

```javascript
const res = await fetch(`https://imhotepexchangeratesapi.pythonanywhere.com/latest_rates/${apiKey}/USD`);
const body = await res.json();
const supported = Object.keys(body.data).map(s => s.toUpperCase()).sort();
console.log(JSON.stringify(supported, null, 2));
```

**Python**

```python
import requests, json

api_key = "YOUR_API_KEY"
url = f"https://imhotepexchangeratesapi.pythonanywhere.com/latest_rates/{api_key}/USD"
data = requests.get(url, timeout=10).json()
supported = sorted({k.upper() for k in data["data"].keys()})
print(json.dumps(supported, indent=2))
```

## Code Examples

### JavaScript (Fetch API)

**Get Latest Rates:**

```javascript
const apiKey = 'YOUR_API_KEY';
const baseCurrency = 'USD';
const url = `https://imhotepexchangeratesapi.pythonanywhere.com/latest_rates/${apiKey}/${baseCurrency}`;

fetch(url)
  .then(response => {
    if (!response.ok) {
      return response.json().then(err => {
        throw new Error(`API Error: ${err.error.message}`);
      });
    }
    return response.json();
  })
  .then(data => {
    console.log('Exchange rates:', data.data);
    console.log(`Last updated: ${data.meta.last_updated_at}`);
    
    // Access specific rate
    const euroRate = data.data.EUR;
    console.log(`1 ${baseCurrency} = ${euroRate} EUR`);
    
    // Check for stale data warning
    if (data.warning) {
      console.warn('Warning:', data.warning.message);
    }
  })
  .catch(error => {
    console.error('Error fetching exchange rates:', error);
  });
```

**Convert Currency:**

```javascript
const apiKey = 'YOUR_API_KEY';
const baseCurrency = 'USD';
const targetCurrency = 'EUR';
const amount = 100;
const url = `https://imhotepexchangeratesapi.pythonanywhere.com/convert/latest_rates/${apiKey}/${baseCurrency}/${targetCurrency}/${amount}`;

fetch(url)
  .then(response => {
    if (!response.ok) {
      return response.json().then(err => {
        throw new Error(`API Error: ${err.error.message}`);
      });
    }
    return response.json();
  })
  .then(data => {
    console.log(`${data.meta.amount} ${data.meta.base_currency} = ${data.data.converted_amount} ${data.meta.target_currency}`);
    console.log(`Conversion rate: ${data.data.conversion_rate}`);
  })
  .catch(error => {
    console.error('Error converting currency:', error);
  });
```

### Python (requests library)

**Get Latest Rates:**

```python
import requests
from datetime import datetime

api_key = 'YOUR_API_KEY'
base_currency = 'USD'
url = f'https://imhotepexchangeratesapi.pythonanywhere.com/latest_rates/{api_key}/{base_currency}'

try:
    response = requests.get(url, timeout=10)
    response.raise_for_status()  # Raise exception for 4XX/5XX responses
    
    data = response.json()
    
    print(f"Exchange rates (base: {data['meta']['base_currency']})")
    print(f"Last updated: {data['meta']['last_updated_at']}")
    
    # Check for stale data warning
    if 'warning' in data:
        print(f"⚠️  Warning: {data['warning']['message']}")
        print(f"   Data age: {data['warning']['data_age']}")
    
    # Print rates for common currencies
    common_currencies = ['EUR', 'GBP', 'JPY', 'CAD', 'AUD', 'CHF', 'CNY']
    for currency in common_currencies:
        if currency in data['data']:
            rate = data['data'][currency]
            print(f"1 {base_currency} = {rate} {currency}")
            
except requests.exceptions.HTTPError as e:
    error_data = e.response.json() if e.response else {}
    print(f"HTTP Error {e.response.status_code}: {error_data.get('error', {}).get('message', str(e))}")
except requests.exceptions.RequestException as e:
    print(f"Request error: {e}")
```

**Convert Currency:**

```python
import requests

api_key = 'YOUR_API_KEY'
base_currency = 'USD'
target_currency = 'EUR'
amount = 100
url = f'https://imhotepexchangeratesapi.pythonanywhere.com/convert/latest_rates/{api_key}/{base_currency}/{target_currency}/{amount}'

try:
    response = requests.get(url, timeout=10)
    response.raise_for_status()
    
    data = response.json()
    
    print(f"{data['meta']['amount']} {data['meta']['base_currency']} = {data['data']['converted_amount']} {data['meta']['target_currency']}")
    print(f"Conversion rate: {data['data']['conversion_rate']}")
    print(f"Last updated: {data['meta']['last_updated_at']}")
    
    if 'warning' in data:
        print(f"⚠️  Warning: {data['warning']['message']}")
        
except requests.exceptions.HTTPError as e:
    error_data = e.response.json() if e.response else {}
    print(f"HTTP Error {e.response.status_code}: {error_data.get('error', {}).get('message', str(e))}")
except requests.exceptions.RequestException as e:
    print(f"Request error: {e}")
```

### cURL

**Get Latest Rates:**

```bash
curl -X GET "https://imhotepexchangeratesapi.pythonanywhere.com/latest_rates/YOUR_API_KEY/USD" \
  -H "Accept: application/json"
```

**Convert Currency:**

```bash
curl -X GET "https://imhotepexchangeratesapi.pythonanywhere.com/convert/latest_rates/YOUR_API_KEY/USD/EUR/100" \
  -H "Accept: application/json"
```

### Node.js (axios)

```javascript
const axios = require('axios');

const apiKey = 'YOUR_API_KEY';
const baseCurrency = 'USD';
const url = `https://imhotepexchangeratesapi.pythonanywhere.com/latest_rates/${apiKey}/${baseCurrency}`;

axios.get(url)
  .then(response => {
    const data = response.data;
    console.log('Exchange rates:', data.data);
    
    if (data.warning) {
      console.warn('Warning:', data.warning.message);
    }
  })
  .catch(error => {
    if (error.response) {
      console.error('API Error:', error.response.data.error.message);
    } else {
      console.error('Request Error:', error.message);
    }
  });
```

## Best Practices

### 1. Error Handling

Always implement proper error handling in your application:

```javascript
try {
  const response = await fetch(url);
  const data = await response.json();
  
  if (!response.ok) {
    // Handle API errors
    console.error('API Error:', data.error.message);
    return;
  }
  
  // Process successful response
  processData(data);
} catch (error) {
  // Handle network errors
  console.error('Network Error:', error);
}
```

### 2. Caching

Cache API responses on your end to reduce API calls and improve performance:

```javascript
const CACHE_DURATION = 5 * 60 * 1000; // 5 minutes
let cachedData = null;
let cacheTimestamp = null;

async function getExchangeRates() {
  const now = Date.now();
  
  // Return cached data if still valid
  if (cachedData && cacheTimestamp && (now - cacheTimestamp) < CACHE_DURATION) {
    return cachedData;
  }
  
  // Fetch fresh data
  const response = await fetch(url);
  const data = await response.json();
  
  // Update cache
  cachedData = data;
  cacheTimestamp = now;
  
  return data;
}
```

### 3. Rate Limiting

Implement request throttling to stay within rate limits:

```javascript
class RateLimiter {
  constructor(maxRequests, windowMs) {
    this.maxRequests = maxRequests;
    this.windowMs = windowMs;
    this.requests = [];
  }
  
  async checkLimit() {
    const now = Date.now();
    this.requests = this.requests.filter(time => now - time < this.windowMs);
    
    if (this.requests.length >= this.maxRequests) {
      const oldestRequest = this.requests[0];
      const waitTime = this.windowMs - (now - oldestRequest);
      await new Promise(resolve => setTimeout(resolve, waitTime));
    }
    
    this.requests.push(Date.now());
  }
}

const limiter = new RateLimiter(30, 60000); // 30 requests per minute
```

### 4. Handle Stale Data Warnings

Always check for and handle stale data warnings:

```javascript
if (data.warning) {
  console.warn(`Using stale data: ${data.warning.data_age}`);
  // Consider showing a user-facing message or using alternative data source
}
```

### 5. Server-Side Requests

**Never expose your API key in client-side code.** Always make API requests from your backend:

```python
# ✅ Good: Backend API route
@app.route('/api/exchange-rates')
def get_rates():
    api_key = os.getenv('EXCHANGE_API_KEY')  # From environment variable
    response = requests.get(f'https://imhotepexchangeratesapi.pythonanywhere.com/latest_rates/{api_key}/USD')
    return response.json()
```

```javascript
// ❌ Bad: Client-side code exposing API key
const apiKey = 'your-api-key'; // Never do this!
fetch(`https://imhotepexchangeratesapi.pythonanywhere.com/latest_rates/${apiKey}/USD`)
```

## Support

For issues, questions, or feature requests, please visit the [homepage](https://imhotepexchangeratesapi.pythonanywhere.com) or contact support.

## Contributing

We welcome contributions! Please visit our [GitHub repository](https://github.com/Imhotep-Tech/imhotep_currency_rates_api) to:
- Report bugs
- Suggest new features
- Submit pull requests
- View the source code

## Repository

- **GitHub Repository:** [https://github.com/Imhotep-Tech/imhotep_currency_rates_api](https://github.com/Imhotep-Tech/imhotep_currency_rates_api)
- **Live API:** [https://imhotepexchangeratesapi.pythonanywhere.com](https://imhotepexchangeratesapi.pythonanywhere.com)
- **Version History:** [https://imhotepexchangeratesapi.pythonanywhere.com/version](https://imhotepexchangeratesapi.pythonanywhere.com/version)

## License

See [LICENSE](LICENSE) file for details.

---

**Last Updated:** January 2025  
**Current Version:** 3.1
