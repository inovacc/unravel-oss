// Native C++ WebView2 host snippet (fixture for inject/webview2 scanner tests).
#include <wrl.h>
#include <WebView2.h>

void InjectScript(ICoreWebView2* webview) {
    webview->AddScriptToExecuteOnDocumentCreated(L"window.x = 1;", nullptr);
}
