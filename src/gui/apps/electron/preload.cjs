/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

const { contextBridge, ipcRenderer } = require('electron');

contextBridge.exposeInMainWorld('electronAPI', {
  onMenuTrigger: (callback) => {
    const subscription = (_event, action) => callback(action);
    ipcRenderer.on('menu-action', subscription);
    return () => {
      ipcRenderer.removeListener('menu-action', subscription);
    };
  }
});
