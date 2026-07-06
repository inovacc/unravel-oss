// SPDX-License-Identifier: BSD-3-Clause
// unravel built-in: defensive analysis instrumentation — IPC logger.
(function () {
  try {
    var electron = require('electron');
    var ipcRenderer = electron && electron.ipcRenderer;
    if (ipcRenderer) {
      var origSend = ipcRenderer.send.bind(ipcRenderer);
      ipcRenderer.send = function () {
        try { console.log('[unravel-ipc] send', Array.prototype.slice.call(arguments)); } catch (_) {}
        return origSend.apply(ipcRenderer, arguments);
      };

      var origOn = ipcRenderer.on.bind(ipcRenderer);
      ipcRenderer.on = function (channel, listener) {
        var wrapped = function () {
          try { console.log('[unravel-ipc] recv', channel, Array.prototype.slice.call(arguments, 1)); } catch (_) {}
          return listener.apply(this, arguments);
        };
        return origOn(channel, wrapped);
      };

      if (typeof ipcRenderer.invoke === 'function') {
        var origInvoke = ipcRenderer.invoke.bind(ipcRenderer);
        ipcRenderer.invoke = function () {
          try { console.log('[unravel-ipc] invoke', Array.prototype.slice.call(arguments)); } catch (_) {}
          return origInvoke.apply(ipcRenderer, arguments);
        };
      }
      console.log('[unravel-ipc] hooks installed (renderer)');
    }
  } catch (_) { /* renderer path unavailable */ }

  try {
    // Main-process visibility — only reachable when nodeIntegration enabled in main.
    var ipcMain = require('electron').ipcMain;
    if (ipcMain && typeof ipcMain.handle === 'function') {
      var origHandle = ipcMain.handle.bind(ipcMain);
      ipcMain.handle = function (channel, listener) {
        var wrapped = function () {
          try { console.log('[unravel-ipc] main.handle', channel, Array.prototype.slice.call(arguments, 1)); } catch (_) {}
          return listener.apply(this, arguments);
        };
        return origHandle(channel, wrapped);
      };
      console.log('[unravel-ipc] hooks installed (main)');
    }
  } catch (_) { /* main path unavailable */ }
})();
