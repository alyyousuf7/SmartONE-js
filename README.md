# SmartONE JS SDK

## Installation
```bash
npm i smartone-js
```

## Usage

### Creating SmartONE instance
Create instance for the first time with login credentials:
```js
import { SmartONE } from 'smartone-js';

const one = await SmartONE.withCredentials('[your-username]', '[your-password]');
const token = one.getToken();
const refreshToken = token.refresh_token;
```

You can reuse the token to create the instance again:
```js
import { SmartONE } from 'smartone-js';

const refreshToken = ...; // your logic to load refresh token
const one = await SmartONE.withRefreshToken(refreshToken);

// Or refresh the token:
const newToken = await one.refreshToken();
const newRefreshToken = newToken.refresh_token;
```
