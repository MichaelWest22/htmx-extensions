htmx.defineExtension('safe-nonce', {
  transformResponse: function(text, xhr, elt) {
    htmx.config.refreshOnHistoryMiss = true // disable ajax fetching on history miss because it doesn't handle nonce replacment
    let replaceRegex = new RegExp(`<script(\\s[^>]*>|>).*?<\\/script(\\s[^>]*>|>)`, 'gis')
    let nonce = xhr.getResponseHeader('HX-Nonce')
    if (!nonce) {
      const csp = xhr.getResponseHeader('content-security-policy')
      if (csp) {
        const cspMatch = csp.match(/(default|script)-src[^;]*'nonce-([^'])'/i)
        if (cspMatch) {
          nonce = cspMatch[2]
        }
      }
    }
    const responseURL = new URL(xhr.responseURL)
    // If request is local and valid nonce then skip removing scripts with this nonce
    if (responseURL.hostname === window.location.hostname && nonce) {
      replaceRegex = new RegExp(`<script(\\s(?!nonce="${nonce.replace(/[\\\[\]\/^*.+?$(){}'#:!=|]/g, '\\$&')}")[^>]*>|>).*?<\\/script(\\s[^>]*>|>)`, 'gis')
    }
    // Now remove all script tags unless they have the a valid nonce
    return text.replace(replaceRegex, '')
  }
})