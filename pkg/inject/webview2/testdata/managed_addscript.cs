// Managed C# WebView2 host snippet (fixture for inject/webview2 scanner tests).
using Microsoft.Web.WebView2.Core;

public class Host {
    public async System.Threading.Tasks.Task InjectAsync(CoreWebView2 webview) {
        await webview.AddScriptToExecuteOnDocumentCreatedAsync("window.x = 1;");
    }
}
