// SPDX-License-Identifier: BSD-3-Clause
// unravel built-in: defensive analysis instrumentation — DevTools enabler.
(function () {
  try {
    // Classic Electron remote path (nodeIntegration:true, contextIsolation:false).
    var remote = require('electron').remote;
    if (remote && remote.getCurrentWindow) {
      var win = remote.getCurrentWindow();
      if (win && win.webContents && typeof win.webContents.openDevTools === 'function') {
        win.webContents.openDevTools({ mode: 'detach' });
        console.log('[unravel-devtools] opened via remote');
        return;
      }
    }
  } catch (_) { /* fall through */ }

  try {
    // contextIsolation:true fallback — request via webFrame postMessage shim.
    var webFrame = require('electron').webFrame;
    if (webFrame && typeof webFrame.executeJavaScript === 'function') {
      webFrame.executeJavaScript("typeof __unravel_open_devtools === 'function' && __unravel_open_devtools();");
      console.log('[unravel-devtools] requested via webFrame');
      return;
    }
  } catch (_) { /* ignore */ }

  console.log('[unravel-devtools] no available path; no-op');
})();
