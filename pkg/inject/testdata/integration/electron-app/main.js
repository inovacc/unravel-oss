// Minimal Electron main process fixture for inject scanner integration test.
// Triggers the scanner's `browser-window-pref:nodeIntegration` and
// `browser-window-pref:contextIsolation` seam emitters.
const { app, BrowserWindow } = require('electron')

function createWindow () {
  const win = new BrowserWindow({
    width: 800,
    height: 600,
    webPreferences: {
      nodeIntegration: true,
      contextIsolation: false,
      preload: 'preload.js',
    },
  })
  win.loadURL('https://example.com')
  win.webContents.openDevTools()
}

app.whenReady().then(createWindow)
