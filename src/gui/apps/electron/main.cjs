/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

const { app, BrowserWindow, Menu, shell } = require('electron');
const path = require('path');

let mainWindow;

function createWindow() {
  mainWindow = new BrowserWindow({
    width: 1280,
    height: 850,
    minWidth: 1024,
    minHeight: 700,
    title: 'USI Software - Sovereign Identity Suite',
    backgroundColor: '#010f1f',
    webPreferences: {
      nodeIntegration: false,
      contextIsolation: true,
      preload: path.join(__dirname, 'preload.cjs'),
      sandbox: true,
    }
  });

  // Check if we are running in development mode
  const isDev = process.argv.includes('--dev');
  if (isDev) {
    mainWindow.loadURL('http://localhost:3000');
    // Open DevTools in developmental state
    mainWindow.webContents.openDevTools();
  } else {
    mainWindow.loadFile(path.join(__dirname, '../dist/index.html'));
  }

  // Set built-in custom OS menu
  const template = [
    {
      label: 'Enclave',
      submenu: [
        { label: 'Unseal Master Session', click: () => { mainWindow.webContents.send('menu-action', 'unseal'); } },
        { label: 'Lock Active Enclave', click: () => { mainWindow.webContents.send('menu-action', 'lock'); } },
        { type: 'separator' },
        { label: 'Purge Sandbox memory', click: () => { mainWindow.webContents.send('menu-action', 'wipe'); } },
        { role: 'quit' }
      ]
    },
    {
      label: 'Cryptography',
      submenu: [
        { label: 'Encrypt File Vault', click: () => { mainWindow.webContents.send('menu-action', 'encrypt'); } },
        { label: 'Decrypt File Vault', click: () => { mainWindow.webContents.send('menu-action', 'decrypt'); } },
        { type: 'separator' },
        { label: 'Sign Document', click: () => { mainWindow.webContents.send('menu-action', 'sign'); } },
        { label: 'Verify Signature', click: () => { mainWindow.webContents.send('menu-action', 'verify'); } }
      ]
    },
    {
      label: 'Sovereign Ledger',
      submenu: [
        { label: 'SPIF Wallet', click: () => { mainWindow.webContents.send('menu-action', 'wallet'); } },
        { label: 'Keypair Manager', click: () => { mainWindow.webContents.send('menu-action', 'keys'); } },
        { label: 'Security Audit Log', click: () => { mainWindow.webContents.send('menu-action', 'security-log'); } }
      ]
    },
    {
      label: 'Window',
      submenu: [
        { role: 'minimize' },
        { role: 'zoom' },
        { type: 'separator' },
        { role: 'togglefullscreen' }
      ]
    },
    {
      label: 'Help',
      submenu: [
        { label: 'Manual & Guide', click: () => { mainWindow.webContents.send('menu-action', 'help-manual'); } },
        { label: 'Export Standalone App', click: () => { mainWindow.webContents.send('menu-action', 'export-instructions'); } },
        { type: 'separator' },
        {
          label: 'Source Code (Vite)',
          click: async () => {
            await shell.openExternal('https://github.com/google/ai-studio');
          }
        }
      ]
    }
  ];

  const menu = Menu.buildFromTemplate(template);
  // Apply the menu
  Menu.setApplicationMenu(menu);

  mainWindow.on('closed', () => {
    mainWindow = null;
  });
}

app.whenReady().then(() => {
  createWindow();

  app.on('activate', () => {
    if (BrowserWindow.getAllWindows().length === 0) {
      createWindow();
    }
  });
});

app.on('window-all-closed', () => {
  if (process.platform !== 'darwin') {
    app.quit();
  }
});
