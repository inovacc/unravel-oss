// SPDX-License-Identifier: BSD-3-Clause
// unravel built-in: defensive analysis instrumentation — network hooks.
(function () {
  if (typeof window === 'undefined') {
    return;
  }

  try {
    if (typeof window.fetch === 'function') {
      var origFetch = window.fetch.bind(window);
      window.fetch = function (input, init) {
        try {
          var url = typeof input === 'string' ? input : (input && input.url) || '<unknown>';
          var method = (init && init.method) || (typeof input === 'object' && input && input.method) || 'GET';
          console.log('[unravel-net] fetch', method, url);
        } catch (_) {}
        return origFetch(input, init);
      };
    }
  } catch (_) { /* ignore */ }

  try {
    if (typeof window.XMLHttpRequest === 'function') {
      var XHR = window.XMLHttpRequest.prototype;
      var origOpen = XHR.open;
      XHR.open = function (method, url) {
        try { this.__unravel_method = method; this.__unravel_url = url; } catch (_) {}
        return origOpen.apply(this, arguments);
      };
      var origSend = XHR.send;
      XHR.send = function (body) {
        try {
          console.log('[unravel-net] xhr', this.__unravel_method || 'GET', this.__unravel_url || '<unknown>',
            body ? '[body]' : '');
        } catch (_) {}
        return origSend.apply(this, arguments);
      };
    }
  } catch (_) { /* ignore */ }

  console.log('[unravel-net] hooks installed');
})();
