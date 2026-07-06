// Hybrid fixture: Electron host that also embeds WebView2 (msedgewebview2.exe sibling).
const { app, BrowserWindow } = require('electron')

app.whenReady().then(() => {
  new BrowserWindow({
    webPreferences: {
      nodeIntegration: true,
      contextIsolation: false,
    },
  })
})
