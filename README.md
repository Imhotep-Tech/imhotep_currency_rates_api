# Imhotep Exchange Rates API

A free, production-ready REST API for retrieving real-time foreign exchange rates and performing currency conversions. Perfect for developers building e-commerce platforms, financial applications, travel services, and any application requiring currency data.

[![GitHub](https://img.shields.io/badge/GitHub-Repository-blue?logo=github)](https://github.com/Imhotep-Tech/imhotep_currency_rates_api)
[![Version](https://img.shields.io/badge/Version-4.0-blue)](https://imhotepexchangeratesapi.pythonanywhere.com/version)
[![License](https://img.shields.io/badge/License-MIT-green)](LICENSE)

---

## Table of Contents

- [System Architecture & Internals](#system-architecture--internals)
- [Database Schema](#database-schema)
- [Caching & Sync Lifecycle](#caching--sync-lifecycle)
- [Features](#features)
- [Base URL & Endpoints](#base-url--endpoints)
  - [Get Latest Exchange Rates](#get-latest-exchange-rates)
  - [Convert Currency Amount](#convert-currency-amount)
- [Response Formats & Errors](#response-formats--errors)
- [Rate Limiting](#rate-limiting)
- [Local Setup & Installation](#local-setup--installation)
- [Contributing Guidelines](#contributing-guidelines)
- [License](#license)

---

## System Architecture & Internals

The Imhotep Exchange Rates API is designed using a multi-tiered architecture that maximizes responsiveness, minimizes external API dependency, and guarantees high availability.

```
                  ┌─────────────────────────────────┐
                  │        Developer Request        │
                  └────────────────┬────────────────┘
                                   │
                                   ▼
                      ┌─────────────────────────┐
                      │    Flask-Limiter WAF    │  (30 reqs/min per key/IP)
                      └────────────┬────────────┘
                                   │
                                   ▼
                      ┌─────────────────────────┐
                      │   API Key Validator     │  (Check users table)
                      └────────────┬────────────┘
                                   │
                                   ▼
                      ┌─────────────────────────┐
                      │  RAM Cache (5m TTL)     │  (Fastest Hit: < 2ms)
                      └────┬────────────────┬───┘
                           │ (Cache Hit)    │ (Cache Miss)
                           ▼                ▼
         ┌──────────────────┐      ┌─────────────────────────┐
         │ Return Response  │      │ SQLite DB Check (Today) │  (Fast Hit: < 8ms)
         └──────────────────┘      └────────┬────────────┬───┘
                                            │ (Valid)    │ (Outdated)
                                            ▼            ▼
                               ┌────────────────┐   ┌───────────────────────────┐
                               │ Populate RAM   │   │ Fetch External API Feed   │
                               │ Cache & Return │   └────────────┬──────────┬───┘
                               └────────────────┘                │ (Success)│ (Fail/Timeout)
                                                                 ▼          ▼
                                                   ┌───────────────┐      ┌─────────────────┐
                                                   │ Write SQLite  │      │ Fallback Stale  │
                                                   │ Cache & Serve │      │ Cache & Warning │
                                                   └───────────────┘      └─────────────────┘
```

### Core Technologies
1. **Core Web Engine**: Python 3 and **Flask** for modular routing via Blueprints.
2. **Database System**: **SQLite** via the CS50/SQLAlchemy wrapper for zero-administration, file-based persistence.
3. **WAF & Security**: **Flask-Limiter** (sliding-window rate-limiting via token buckets) and **Flask-Talisman** for strict HTTP header security policies (CSP, X-Frame-Options, X-Content-Type-Options).
4. **OAuth Core**: **Authlib** client wrappers to coordinate Google OAuth Single Sign-on.
5. **Session Management**: File-system-based **Flask-Session** variables.

---

## Database Schema

The SQLite database contains 3 core tables to manage keys, rates caches, and raw provider feeds.

### 1. `users`
Stores guest keys as well as permanent developer profiles.
```sql
CREATE TABLE users(
    user_id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_username TEXT,
    user_password TEXT,
    user_mail TEXT,
    user_mail_verify TEXT, -- 'verified', 'not_verified', or 'guest'
    api_key TEXT UNIQUE
);
```

### 2. `api_data`
Stores the raw JSON representation of exchange feeds to keep a history of updates and timestamps.
```sql
CREATE TABLE api_data (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    base_currency TEXT NOT NULL,      -- defaults to 'USD'
    last_updated_at TEXT NOT NULL,    -- ISO 8601 provider timestamp
    json_data TEXT NOT NULL           -- raw JSON payload
);
```

### 3. `currencies`
Relational mapping of individual rates parsed from the raw feed for quick calculation.
```sql
CREATE TABLE currencies (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    api_data_id INTEGER NOT NULL,
    currency_code TEXT NOT NULL,      -- ISO currency uppercase (e.g. 'EUR')
    rate REAL NOT NULL,               -- relative value to USD
    FOREIGN KEY(api_data_id) REFERENCES api_data(id) ON DELETE CASCADE
);
```

---

## Caching & Sync Lifecycle

Our synchronization model ensures the external API endpoint (configured via `CURRENCY_API_URL`) is never called unnecessarily, defending the service from provider rate exhausts.

### Cache Verification Flow
1. **Memory Hit (TTL 5 mins)**:
   We store currency structures in a Python global dictionary `RATES_CACHE`. If the user queries within 5 minutes of our last lookup and the server hasn't changed dates, we bypass SQLite entirely.
2. **SQLite Database Hit**:
   If 5 minutes have elapsed, we query the `api_data` table. If the `last_updated_at` date corresponds to the current UTC date, we reload `RATES_CACHE` from SQLite and return the rates immediately.
3. **On-Demand Fetch Sync**:
   If the database entry is outdated (older than today), we trigger an asynchronous HTTP `GET` call to the external rate feed:
   - **On Success**: We parse the payload. If rates have changed since the last update, we write the new JSON payload to `api_data`, delete older caches, update records in `currencies`, reload the memory cache, and return.
   - **On Fail (Timeout/Offline)**: We trigger a **Graceful Fallback**. The system fetches the latest available rate records from SQLite (even if stale), formats the JSON return, and appends a `warning` payload displaying data age (e.g., `data_age: "3 days old"`).

---

## Features

- **Guest Onboarding**: Instantly generate a temporary key directly on the landing page via 1-click. Stored locally in `localStorage` for sandbox experiments.
- **Interactive Sandbox Explorer**: Try rates and conversions directly in a web playground terminal.
- **Graceful Fallback Cache**: High availability even when external feeds fail.
- **RESTful standard schemas**: Structured JSON returns with numeric HTTP status validation.
- **Google OAuth Integration**: Log in instantly with your Google account credentials.
- **Security Protocols**: Enforced Content Security Policy (CSP) headers via Flask-Talisman.

---

## Base URL & Endpoints

```
https://imhotepexchangeratesapi.pythonanywhere.com
```

### Get Latest Exchange Rates
Retrieve daily rates relative to a specified base currency.

* **URL:** `/latest_rates/{api_key}/{base_currency}`
* **Method:** `GET`
* **Path Parameters:**
  - `api_key` (string): Your personal key or anonymous guest key.
  - `base_currency` (string): ISO 4217 code (e.g. `USD`, `EUR`, `EGP`). Case-insensitive.

**Sample Request:**
```bash
curl https://imhotepexchangeratesapi.pythonanywhere.com/latest_rates/YOUR_API_KEY/USD
```

**Success Response (200 OK):**
```json
{
  "meta": {
    "base_currency": "USD",
    "last_updated_at": "2026-05-30T18:00:00"
  },
  "data": {
    "EUR": 0.92,
    "GBP": 0.79,
    "EGP": 47.30
  }
}
```

---

### Convert Currency Amount
Calculate currency conversions directly on our API server.

* **URL:** `/convert/latest_rates/{api_key}/{base_currency}/{target_currency}/{amount}`
* **Method:** `GET`
* **Path Parameters:**
  - `api_key` (string): Your API key.
  - `base_currency` (string): Convert from.
  - `target_currency` (string): Convert to.
  - `amount` (integer): Value to convert (positive integer).

**Sample Request:**
```bash
curl https://imhotepexchangeratesapi.pythonanywhere.com/convert/latest_rates/YOUR_API_KEY/USD/EUR/100
```

**Success Response (200 OK):**
```json
{
  "meta": {
    "base_currency": "USD",
    "target_currency": "EUR",
    "amount": 100,
    "last_updated_at": "2026-05-30T18:00:00"
  },
  "data": {
    "conversion_rate": 0.92,
    "converted_amount": 92.00
  }
}
```

---

## Response Formats & Errors

All errors return a structured JSON response with numeric status codes.

```json
{
  "error": {
    "code": 401,
    "message": "Invalid API key"
  }
}
```

| Code | Type | Cause |
|------|------|-------|
| **400** | Bad Request | Missing params or unsupported currency codes |
| **401** | Unauthorized | Missing, expired, or invalid API key |
| **429** | Too Many Requests | Key or IP exceeded the 30 reqs/min rate limit |
| **503** | Service Unavailable | External rate provider is down and database cache is empty |

---

## Rate Limiting

The API rate limits are applied via **Flask-Limiter** using sliding window token buckets.
- **Standard limits**: 30 requests per minute per IP address / API key.
- when exceeded, the API returns a `429 Too Many Requests` error.

---

## Local Setup & Installation

Follow these instructions to spin up the REST server locally for development or testing:

### Prerequisites
- Python 3.9+
- SQLite 3
- Git

### 1. Clone the repository
```bash
git clone https://github.com/Imhotep-Tech/imhotep_currency_rates_api.git
cd imhotep_currency_rates_api
```

### 2. Configure Virtual Environment
```bash
# Create environment
python3 -m venv venv

# Activate environment (Mac/Linux)
source venv/bin/activate

# Windows activation
# venv\Scripts\activate
```

### 3. Install Dependencies
```bash
pip install -r requirements.txt
```

### 4. Setup Environment Variables
Create a `.env` file in the root folder of the project:
```env
DATABASE_URL=sqlite:///imhotep_exchange_rate_api.db
secret_key=your_flask_session_secret_key
CURRENCY_API_URL=https://cdn.jsdelivr.net/npm/@fawazahmed0/currency-api@latest/v1/currencies
MAIL_PASSWORD=your_gmail_app_password_if_using_mail_alerts

# Google OAuth (Optional)
GOOGLE_CLIENT_ID=your_google_oauth_client_id
GOOGLE_CLIENT_SECRET=your_google_oauth_client_secret
```

### 5. Run Database migrations
SQLite database tables migrate automatically on boot when the Flask app starts. If you want to check seed logs:
```bash
sqlite3 imhotep_exchange_rate_api.db
```

### 6. Launch server
```bash
python app.py
```
The server will boot on `http://127.0.0.1:5000`. You can test endpoints locally:
```bash
curl http://127.0.0.1:5000/latest_rates/demo/USD
```

---

## Contributing Guidelines

We love contributions! Follow these steps to submit pull requests:

1. **Fork the Repository**: Create your own copy of the repository on GitHub.
2. **Setup Branches**: Create a descriptive feature branch from main:
   ```bash
   git checkout -b feature/your-awesome-change
   ```
3. **Local Checks**: Ensure you are not exposing secrets or hardcoding credentials. Verify code logic locally by launching the Flask app.
4. **Submit PR**: Open a pull request against our `main` branch. Provide a clear summary of what you did, referencing any issues.

---

## License

This project is licensed under the MIT License. See [LICENSE](LICENSE) for details.
