'use strict';
// The ONLY bridge between the window and the computer. Everything is a narrow, validated call.
const { contextBridge, ipcRenderer, webUtils } = require('electron');

const listeners = new Set();
ipcRenderer.on('sg:progress', (_e, p) => listeners.forEach((fn) => fn(p)));

contextBridge.exposeInMainWorld('sg', {
  pathsFromDrop: (files) => Array.from(files || []).map((f) => webUtils.getPathForFile(f)).filter(Boolean),
  pick: (kind) => ipcRenderer.invoke('sg:pick', kind),
  classify: (paths) => ipcRenderer.invoke('sg:classify', paths),
  scan: (drop) => ipcRenderer.invoke('sg:scan', drop),
  protect: (drop) => ipcRenderer.invoke('sg:protect', drop),
  getSettings: () => ipcRenderer.invoke('sg:settings:get'),
  setSettings: (s) => ipcRenderer.invoke('sg:settings:set', s),
  chooseOutDir: () => ipcRenderer.invoke('sg:outdir'),
  reveal: (p) => ipcRenderer.invoke('sg:reveal', p),
  readReport: (p) => ipcRenderer.invoke('sg:readReport', p),
  onProgress: (fn) => {
    listeners.add(fn);
    return () => listeners.delete(fn);
  },
  version: () => ipcRenderer.invoke('sg:version'),
});
