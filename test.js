
// File: public/index.html


// File: .env
PORT=3000
ONMETA_API_KEY=your_onmeta_api_key_here

// File: package.json
{
  "name": "nodejs-onramp-app",
  "version": "1.0.0",
  "description": "A simple token onramp application using Node.js and OnMeta",
  "main": "app.js",
  "scripts": {
    "start": "node app.js"
  },
  "dependencies": {
    "axios": "^0.21.1",
    "dotenv": "^10.0.0",
    "express": "^4.17.1"
  }
}