# Imhotep Exchange Rates API

## Overview

The Currency Exchange API allows users to retrieve real-time foreign exchange rates for various currencies. This API is perfect for developers who want to integrate currency conversion features into their applications, whether for e-commerce, finance, or travel services. Best of all, it is completely free to use!

## Features

- **Completely Free**: No hidden costs or subscription fees, making it accessible for all users.
- **Real-time Exchange Rates**: Fetch the latest currency rates with a simple API call.
- **Customizable Base Currency**: Specify the base currency for conversion, allowing flexibility in financial calculations.
- **Secure API Access**: Each user is provided with a unique API key to ensure secure and personalized access.

## Getting Started

### 1. Sign Up and Get Your API Key
   - Register on the homepage to receive your free API key.
   - Each user is granted one API key which must be included in the URL for each API request.
### 2. API Endpoints

#### Fetch Latest Exchange Rates
  - **Endpoint**: `/latest_rates/<api_key>/<base_currency>`
  - **Method**: `GET`
  - **Parameters**:
    - `api_key` (required): Your unique API key, which you received upon registration.
    - `base_currency` (required): The base currency for which exchange rates should be calculated, e.g., USD, EUR.
  - **Example Request**:
    
    ```
    GET https://imhotepexchangeratesapi.pythonanywhere.com/latest_rates/<your_api_key>/USD
    ```

#### Convert Currency Amount
  - **Endpoint**: `/convert/latest_rates/<api_key>/<base_currency>/<target_currency>/<amount>`
  - **Method**: `GET`
  - **Parameters**:
    - `api_key` (required): Your unique API key
    - `base_currency` (required): The currency to convert from
    - `target_currency` (required): The currency to convert to
    - `amount` (required): The amount to convert (integer)
  - **Example Request**:
    
    ```
    GET https://imhotepexchangeratesapi.pythonanywhere.com/convert/latest_rates/<your_api_key>/USD/EUR/100
    ```

  - **Response**: Returns a JSON object containing:
     - `meta`: Information about the request, including currencies, amount, and timestamp.
     - `data`: Conversion rate and converted amount.
       
#### Sample Response:
``` json
{
  "meta": {
    "base_currency": "USD",
    "last_updated_at": "2024-10-25T15:00:00"
  },
  "data": {
    "EUR": 0.85,
    "JPY": 110.45,
    "GBP": 0.75,
    ...
  }
}

```

## Usage Example
### 1.Get Exchange Rates for EUR:

```

GET https://imhotepexchangeratesapi.pythonanywhere.com/latest_rates/<your api key>/EUR

```

### 2. Change Base Currency to EGP:
```

GET https://imhotepexchangeratesapi.pythonanywhere.com/latest_rates/<your api key>/EGP

```

## Error Handling
If there are issues with your request, such as an invalid API key or unsupported base currency, you will receive an error response:

``` json

{
  "error": "Error message here"
}


```

## Rate Limiting

Each API key allows for **unlimited** requests per month.
