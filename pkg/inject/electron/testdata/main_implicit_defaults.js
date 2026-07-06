// Hand-written minimal Electron main with NO webPreferences. Ground truth:
// no high/medium seams; only framework-default inferences (low confidence)
// should be omitted because there is no webPreferences block to anchor to.
// Expectation: zero seams emitted.
const { app, BrowserWindow } = require('electron');

function createWindow() {
  const win = new BrowserWindow({
    width: 800,
    height: 600
  });
  win.loadURL('https://example.com');
}

app.whenReady().then(createWindow);
