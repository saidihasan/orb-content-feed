(() => {
  'use strict';

  function loadError(code, message, cause) {
    const error = new Error(message);
    error.name = 'ORBFeedLoadError';
    error.code = code;
    if (cause) error.cause = cause;
    return error;
  }

  async function loadActiveFeed(url, options = {}) {
    const fetchImpl = options.fetchImpl || globalThis.fetch;
    const validateFeed = options.validateFeed;
    const timeoutMs = Number.isFinite(options.timeoutMs) ? options.timeoutMs : 12000;
    if (typeof fetchImpl !== 'function') throw loadError('network', 'Fetch tidak tersedia.');
    if (typeof validateFeed !== 'function') throw loadError('validation', 'Validator feed tidak tersedia.');

    const controller = typeof AbortController === 'function' ? new AbortController() : null;
    const timeoutId = controller ? setTimeout(() => controller.abort(), timeoutMs) : null;
    let response;
    try {
      response = await fetchImpl(url, {
        cache: 'no-store',
        headers: { Accept: 'application/json' },
        signal: controller?.signal,
      });
    } catch (error) {
      const timedOut = error?.name === 'AbortError';
      throw loadError(timedOut ? 'timeout' : 'network', timedOut ? 'Waktu pemuatan feed habis.' : 'Feed aktif tidak dapat dijangkau.', error);
    } finally {
      if (timeoutId) clearTimeout(timeoutId);
    }

    if (!response?.ok) throw loadError('http', `Feed aktif merespons dengan status ${response?.status || 'tidak diketahui'}.`);
    let candidate;
    try {
      candidate = await response.json();
    } catch (error) {
      throw loadError('json', 'Respons feed aktif bukan JSON yang valid.', error);
    }
    try {
      validateFeed(candidate);
    } catch (error) {
      throw loadError('validation', `Feed aktif tidak valid: ${error.message}`, error);
    }
    return candidate;
  }

  globalThis.ORBFeedLoader = Object.freeze({ loadActiveFeed });
})();
