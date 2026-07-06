// WebView2 embed sibling — registers AddScriptToExecuteOnDocumentCreatedAsync.
using Microsoft.Web.WebView2.Core;

public class Embed
{
    public static async System.Threading.Tasks.Task Setup(CoreWebView2 w)
    {
        await w.AddScriptToExecuteOnDocumentCreatedAsync("window.h = 1;");
    }
}
