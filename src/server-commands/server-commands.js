/*
  Server Commands Extension (<htmx> tags)
  ======================================================
  This extension enables out-of-band swaps on steroids using custom <htmx> elements in a server response.
  It lets you send commands for swapping content, triggering events, and managing browser history.

  It is inspired by Rails' <turbo-stream>, data-star, and is compatible with the sse & websockets extensions out of the box.
*/
(function () {
    /** @type {import("../htmx").HtmxInternalApi} */
    let api;

    // <htmx> tag valid attributes
    const ATTRIBUTES = new Set([
        'target',
        'swap',
        'select',
        'redirect',
        'refresh',
        'location',
        'push-url',
        'replace-url',
        'trigger',
        'trigger-after-swap',
        'trigger-after-settle',
    ]);

    const HISTORY_MARKER = 'htmx-server-commands-history-only';

    htmx.defineExtension('server-commands', {
        /** @param {import("../htmx").HtmxInternalApi} apiRef */
        init: function (apiRef) {
            api = apiRef;
        },

        /**
         * Intercepts htmx events to handle fake header requests.
         * @param {string} name - The event name
         * @param {Event} evt - The event object
         */
        onEvent: function (name, evt) {
            if (name === "htmx:beforeRequest" && evt.detail.pathInfo?.requestPath.startsWith(HISTORY_MARKER)) {
                const url = new URL(evt.detail.pathInfo?.requestPath, window.location.origin);
                const headerName = url.searchParams.get("header");
                const headerValue = url.searchParams.get("value");

                evt.detail.xhr.getResponseHeader = function(header) {
                    return header.toLowerCase() === headerName.toLowerCase() ? headerValue : null;
                };
                evt.detail.xhr.getAllResponseHeaders = function() {
                    return headerName + ": " + headerValue;
                };
                Object.defineProperty(evt.detail.xhr, "status", { value: 200, writable: false });
                evt.detail.keepIndicators = true; // prevent indicator cleanup when indicators will not be generated
                evt.detail.xhr.onload();
                return false;
            }
        },

        /**
         * @param {string} text
         * @param {XMLHttpRequest} xhr
         * @param {Element} elt - The element that triggered the request (with hx-get/hx-post/etc. or sse-connect)
         */
        transformResponse: function (text, xhr, elt) {
            const triggeringElement = elt;

            // Check if empty text, or no <htmx> tags
            const fragment = text ? api.makeFragment(text) : null;
            if (!fragment || !fragment.querySelector('htmx')) {
                return text; // Return early
            }

            // Find all <htmx> tags
            const commandElements = fragment.querySelectorAll('htmx');

            // Keep only top-level ones (direct children of the fragment)
            const topLevelCommandElements = Array.from(commandElements).filter(el => {
                // Check if this htmx element is a direct child of the fragment
                return el.parentNode === fragment;
            });

            if (commandElements.length > topLevelCommandElements.length) {
                console.warn(
                    '[server-commands] Nested <htmx> tags are not supported and will be discarded.'
                );
            }

            // Process ONLY the top-level <htmx> tags in order
            for (const commandElement of topLevelCommandElements) {
                processCommandElement(commandElement, triggeringElement);
            }

            // Remove all <htmx> tags from the fragment
            commandElements.forEach(el => el.remove());

            // Serialize remaining nodes into an HTML string
            const container = document.createElement('div');
            container.appendChild(fragment);

            return container.innerHTML;
        },
    });

    /**
     * Processes a single <htmx> element by reading its attributes and executing
     * actions in a fixed, sequential order.
     * @param {HTMLElement} commandElement - The <htmx> element to process
     * @param {Element} triggeringElement - The element that triggered the request (e.g. with hx-get/hx-post/etc. or sse-connect)
     */
    function processCommandElement(commandElement, triggeringElement) {
        try {
            // Fire cancelable event
            if (api.triggerEvent(triggeringElement, 'htmx:beforeServerCommand', { commandElement }) === false) return;

            validateCommandElement(commandElement);

            const swapStyle = api.getAttributeValue(commandElement, "swap") || "outerHTML";
            const select = api.getAttributeValue(commandElement, "select");
            const targetSelector = api.getAttributeValue(commandElement, "target");
            const sourceSelector = api.getAttributeValue(commandElement, "source");
            const sourceMode = api.getAttributeValue(commandElement, "source-mode") || "clone";

            let targetElement = null;
            let swapContent = null;

            if (targetSelector) {
                targetElement = htmx.find(targetSelector);
                if (targetElement) {
                    swapContent = commandElement.innerHTML;
                } else {
                    const error = new Error(`[server-commands] Target selector "${targetSelector}" did not match any elements.`);
                    api.triggerErrorEvent(triggeringElement, 'htmx:targetError', { error: error, target: targetSelector });
                }
            }

            if (api.hasAttribute(commandElement, 'trigger')) {
                fakeHeaderRequest('HX-Trigger', api.getAttributeValue(commandElement, 'trigger'));
            }
            if (api.hasAttribute(commandElement, 'location')) {
                fakeHeaderRequest('HX-Location', api.getAttributeValue(commandElement, 'location'));
            }
            if (api.hasAttribute(commandElement, 'redirect')) {
                window.location.href = api.getAttributeValue(commandElement, 'redirect');
                return; // Stop processing
            }
            if (api.hasAttribute(commandElement, 'refresh') && api.getAttributeValue(commandElement, 'refresh') !== 'false') {
                window.location.reload();
                return; // Stop processing
            }

            if (api.hasAttribute(commandElement, 'push-url')) {
                fakeHeaderRequest('HX-Push-Url', api.getAttributeValue(commandElement, 'push-url'));
            }
            if (api.hasAttribute(commandElement, 'replace-url')) {
                fakeHeaderRequest('HX-Replace-Url', api.getAttributeValue(commandElement, 'replace-url'));
            }

            // Process swap if target was found
            if (targetElement && swapContent !== null) {
                const beforeSwapDetails = {
                    elt: triggeringElement,
                    target: targetElement,
                    swapSpec: swapSpec,
                    serverResponse: swapContent,
                    shouldSwap: true,
                    fromServerCommand: true
                };

                // Fire cancelable event
                if (api.triggerEvent(targetElement, 'htmx:beforeSwap', beforeSwapDetails) !== false) {
                    if (beforeSwapDetails.shouldSwap) {
                        api.swap(
                            beforeSwapDetails.target,
                            beforeSwapDetails.serverResponse,
                            beforeSwapDetails.swapSpec,
                            {
                                select: select,
                                eventInfo: { elt: triggeringElement },
                                contextElement: triggeringElement,
                                afterSwapCallback: api.hasAttribute(commandElement, 'trigger-after-swap')
                                    ? () => fakeHeaderRequest('HX-Trigger', api.getAttributeValue(commandElement, 'trigger-after-swap'))
                                    : undefined,
                                afterSettleCallback: api.hasAttribute(commandElement, 'trigger-after-settle')
                                    ? () => fakeHeaderRequest('HX-Trigger', api.getAttributeValue(commandElement, 'trigger-after-settle'))
                                    : undefined
                            }
                        );
                    }
                }
            }

            api.triggerEvent(triggeringElement, 'htmx:afterServerCommand', { commandElement: commandElement });
        } catch (error) {
            // Fire the public event for programmatic listeners.
            api.triggerErrorEvent(
                document.body, 'htmx:serverCommandError', {error: error, commandElement: commandElement}
            );
        }
    }

    /**
     * Validate <htmx> element & throw an error for unknown attributes or invalid combinations.
     * @param {HTMLElement} element
     * @throws {Error} If validation fails
     */
    function validateCommandElement(element) {
        const errors = [];

        const hasCommandAttribute = Array.from(element.attributes).some(attr => ATTRIBUTES.has(attr.name));
        if (!hasCommandAttribute) {
            const elementHTML = element.outerHTML.replace(/\s*\n\s*/g, " ").trim();
            throw new Error(`[server-commands] The following <htmx> tag has no command attributes:\n\n  ${elementHTML}\n`);
        }

        // Check unknown attributes
        for (const attr of element.attributes) {
            if (!ATTRIBUTES.has(attr.name)) {
                errors.push(
                    `Invalid attribute '${attr.name}'. Valid attributes are: ${[...ATTRIBUTES].join(', ')}`
                );
            }
        }

        // Check invalid combinations
        const hasSwapOrSelect = api.hasAttribute(element, 'swap') || api.hasAttribute(element, 'select');
        const hasTarget = api.hasAttribute(element, 'target');
        const hasSource = api.hasAttribute(element, "source");
        const hasContent = element.innerHTML.trim().length > 0;

        if (hasSwapOrSelect && !hasTarget) {
            errors.push(
                `A command with 'swap' or 'select' performs a swap and requires a target. Specify the target using the 'target' attribute: <htmx target="#my-div">...</htmx>`
            );
        }

        if (hasSource && hasContent) {
            errors.push(
                `Cannot specify both 'source' attribute and inner content. Use 'source' to reference client-side content OR provide server-sent content inside the tag.`
            );
        }

        // If errors were found, throw an error with details
        if (errors.length > 0) {
            const elementHTML = element.outerHTML.replace(/\s*\n\s*/g, " ").trim();
            const errorIntro = `[server-commands] ${errors.length} validation error(s) for command:`;
            const errorDetails = errors.map(e => `  - ${e}`).join('\n');

            throw new Error(`${errorIntro}\n\n  ${elementHTML}\n\n${errorDetails}\n`);
        }
    }

    /**
     * Triggers a fake AJAX request to inject response headers into htmx's processing pipeline.
     * @param {string} header - The response header name (e.g., 'HX-Trigger', 'HX-Push-Url')
     * @param {string} value - The response header value
     */
    function fakeHeaderRequest(header, value) {
        htmx.ajax('get', HISTORY_MARKER + '?header=' + header + '&value=' + encodeURIComponent(value), { swap: 'none' });
    }
})();