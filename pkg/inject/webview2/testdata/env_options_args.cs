// Managed C# WebView2 environment options snippet.
using Microsoft.Web.WebView2.Core;

public class EnvSetup {
    public CoreWebView2EnvironmentOptions Configure() {
        var options = new CoreWebView2EnvironmentOptions();
        options.AdditionalBrowserArguments = "--remote-debugging-port=9222";
        return options;
    }
}
