# Sphinx Ledger Explorer

An interactive, ultra-modern block explorer and cryptographic laboratory for **Sphinx** — the world's first post-quantum secure ledger utilizing SPHINCS+ signatures.

## Overview

The Sphinx Ledger Explorer is a React-based single-page application (SPA) that provides a graphical interface for browsing the Sphinx blockchain. It displays blocks, transactions, accounts, and network statistics by communicating with the Sphinx Go backend API.

## Architecture

```
┌─────────────────────┐      /api/*      ┌──────────────────────┐
│                     │  ──────────────>  │                      │
│  React Frontend     │   proxy pass      │  Go Backend Node     │
│  (Vite dev server)  │  <──────────────  │  (HTTP server)       │
│  port 3000          │      JSON         │  port 8545 (default) │
│                     │                   │                      │
└─────────────────────┘                   └──────────────────────┘
```

The Vite development server proxies all `/api/*` requests to the Go backend HTTP server. This avoids CORS issues during development.

## Prerequisites

### Required Software

| Software | Minimum Version | Installation Command |
|----------|----------------|---------------------|
| **Node.js** | 20.x | `brew install node` (macOS) or `apt install nodejs npm` (Linux) |
| **npm** | 9.x | (comes with Node.js) |
| **Go** | 1.21 | `brew install go` (macOS) or `apt install golang` (Linux) |
| **Git** | any | `brew install git` (macOS) or `apt install git` (Linux) |

### Verify Installation

Run these commands to confirm everything is installed:

```bash
node --version    # should show v20.x or higher
npm --version     # should show 9.x or higher
go version        # should show go1.21 or higher
git --version     # should show a version number
```

### Clone the Repository (if not already done)

```bash
git clone https://github.com/sphinxfndorg/protocol.git
cd protocol
```

## Quick Start (Local Development)

### Step 1: Install Frontend Dependencies

```bash
cd src/explorer
npm install
```

This installs all required packages: React, Vite, Tailwind CSS, Lucide icons, Framer Motion, and more.

### Step 2: Start the Go Backend Node

Open a **new terminal** (keep the first one open) and start a Sphinx validator node. This node provides the blockchain data via its HTTP API:

```bash
cd Desktop/protocol
go run src/cli/main.go node --role=validator \
    --tcp-addr=127.0.0.1:30303 \
    --http-port=127.0.0.1:8545 \
    --datadir=data/node1 \
    --nodes=3 --node-index=0 \
    --pbft
```

> **Note:** The `--http-port` flag determines which port the API server listens on. The default is `8545`. If you use a different port, update the proxy target in `vite.config.ts` accordingly.

### Step 3: Start the Frontend (Development Mode)

In the **first terminal** (where you ran `npm install`), run:

```bash
npm run dev
```

The Vite dev server will start at **http://localhost:3000/**.

### Step 4: Open the Explorer

Open your browser to [http://localhost:3000/](http://localhost:3000/).

You should see the Sphinx Ledger Explorer interface with blockchain data loaded from your local node.

## Running with Multiple Backend Nodes

If you have multiple Sphinx nodes running (e.g., a 3-validator PBFT network), you can point the explorer at any of them by changing the proxy target in `vite.config.ts`:

```ts
proxy: {
  '/api': {
    target: 'http://localhost:8545',  // change to 8546, 8547, etc.
    changeOrigin: true,
    secure: false,
  },
},
```

## Building for Production

To create a production build of the frontend:

```bash
cd src/explorer
npm run build
```

This generates static files in the `dist/` directory. The Go backend server can serve these files directly (it has a built-in static file server at the `/explorer/` path).

To preview the production build locally:

```bash
npm run preview
```

## Available Scripts

| Script | Description |
|--------|-------------|
| `npm run dev` | Start Vite dev server on port 3000 |
| `npm run build` | Build for production into `dist/` |
| `npm run preview` | Preview the production build |
| `npm run clean` | Remove `dist/` and `server.js` |
| `npm run lint` | Run TypeScript type checking |

## Configuration

### Proxy Target

The Vite dev server proxies `/api` requests to the Go backend. The target is configured in `vite.config.ts`:

```ts
proxy: {
  '/api': {
    target: 'http://localhost:8545',  // Go backend HTTP port
    changeOrigin: true,
    secure: false,
  },
},
```

If your backend node uses a different HTTP port (e.g., `--http-port=127.0.0.1:8546`), update this value.

### Port

The dev server runs on port 3000 by default. To change this, modify the `--port` flag in `package.json`:

```json
"dev": "vite --port=3000 --host=0.0.0.0"
```

## Project Structure

```
src/explorer/
├── dist/                  # Production build output
├── node_modules/          # npm dependencies
├── src/                   # React application source
│   ├── main.tsx           # Entry point
│   └── ...                # Components, pages, hooks, etc.
├── index.html             # HTML template
├── metadata.json          # App metadata
├── package.json           # npm dependencies and scripts
├── tsconfig.json          # TypeScript configuration
├── vite.config.ts         # Vite configuration (proxy, plugins)
└── README.md              # This file
```

## Troubleshooting

### "Connection Error" or "500 Internal Server Error"

This means the frontend cannot reach the Go backend API. Check:

1. Is the Go backend node running? Run `ps aux | grep "go run"` to verify.
2. Is the backend listening on the expected port? Run `lsof -i -P -n | grep LISTEN` to check.
3. Does the proxy target in `vite.config.ts` match the backend's `--http-port`?

### "ECONNREFUSED" in Vite terminal output

The Vite proxy cannot connect to the backend. Ensure the Go node is running and the port is correct.

### Blank page or no data

- Check the browser's developer console for errors.
- Verify the backend API is responding: `curl http://localhost:8545/api/v1/explorer/blocks?page=1&limit=5`