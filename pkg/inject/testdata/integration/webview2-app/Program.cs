// Minimal C# WebView2 host fixture for inject scanner integration test.
// Triggers `webview2-add-script` and `webview2-web-message` seam emitters.
using Microsoft.Web.WebView2.Core;

public class Program
{
    public static async System.Threading.Tasks.Task Setup(CoreWebView2 webview)
    {
        await webview.AddScriptToExecuteOnDocumentCreatedAsync("window.injected = true;");
        webview.WebMessageReceived += (s, e) => System.Console.WriteLine(e.WebMessageAsJson);
    }
}
