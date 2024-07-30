htmx.defineExtension('safe-nonce', {
  transformResponse: function(text, xhr, elt) {
    htmx.config.refreshOnHistoryMiss = true // disable ajax fetching on history miss because it doesn't handle nonce replacment
    let replaceRegex = new RegExp(`<script(\\s[^>]*>|>).*?<\\/script(\\s[^>]*>|>)`, 'gis')
    let nonce = xhr.getResponseHeader('HX-Nonce')
    if (!nonce) {
      const csp = xhr.getResponseHeader('content-security-policy')
      if (csp) {
        const cspMatch = csp.match(/(default|script)-src[^;]*'nonce-([^']*)'/i)
        if (cspMatch) {
          nonce = cspMatch[2]
        }
      }
    }
    if (window.location.hostname) {
      const responseURL = new URL(xhr.responseURL)
      if (responseURL.hostname !== window.location.hostname) {
        nonce = '' // ignore nonce header if request is not some domain 
      }
    }
    if (nonce) {
      replaceRegex = new RegExp(`<script(\\s(?!nonce="${nonce.replace(/[\\\[\]\/^*.+?$(){}'#:!=|]/g, '\\$&')}")[^>]*>|>).*?<\\/script(\\s[^>]*>|>)`, 'gis')
    }
    return text.replace(replaceRegex, '')
  }
})