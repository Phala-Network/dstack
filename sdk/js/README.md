# Tappd SDK

This SDK provides a TypeScript client for communicating with a Tappd server via Unix Domain Socket.

## Installation

```bash
npm install tappd-sdk
```

## Usage

```typescript
import { TappdClient } from 'tappd-sdk';

const client = new TappdClient('/path/to/tappd.sock');
client.deriveKey('/', 'mySubject')
  .then(result => console.log(result))
  .catch(error => console.error(error));
```


## Development

1. Clone the repository
2. Install dependencies: `npm install`
3. Build the project: `npm run build`
4. Run tests: `npm test`

## License

Apache License
