// Hand-written minimal Electron main with explicit, dangerous webPreferences.
// Ground truth seam expectations:
//   - browser-window-pref:nodeIntegration  (high)
//   - browser-window-pref:contextIsolation (high)
//   - browser-window-pref:sandbox          (high)
//   - preload-script                       (high if preload.js exists alongside)
//   - executejavascript-call               (high)
//   - command-line-switch:remote-debugging (high)
const { app, BrowserWindow } = require('electron');
const path = require('path');

app.commandLine.appendSwitch("remote-debugging-port", "9222");

function createWindow() {
  const win = new BrowserWindow({
    width: 800,
    height: 600,
    webPreferences: {
      nodeIntegration: true,
      contextIsolation: false,
      sandbox: false,
      preload: path.join(__dirname, 'preload.js')
    }
  });
  win.loadURL('https://example.com');
  win.webContents.executeJavaScript("window.alert('injected')");
}

app.whenReady().then(createWindow);
