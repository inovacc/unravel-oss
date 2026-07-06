// Managed C# WebView2 web-message handler snippet.
using Microsoft.Web.WebView2.Core;

public class Bridge {
    public void Wire(CoreWebView2 webview) {
        webview.WebMessageReceived += OnMessage;
    }

    private void OnMessage(object sender, CoreWebView2WebMessageReceivedEventArgs e) {
        // host-side handling
    }
}
