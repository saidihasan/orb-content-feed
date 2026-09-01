import assert from 'node:assert/strict';
import { before, describe, test } from 'node:test';

before(async () => {
  await import('../public/feed-loader.js');
});

function validFeed() {
  return { feed_name: 'ORB', updated_at: '2026-09-01T09:00:00+07:00', items: [] };
}

function validateFeed(candidate) {
  if (!candidate || typeof candidate.feed_name !== 'string' || !Array.isArray(candidate.items)) {
    throw new Error('struktur feed tidak valid');
  }
  return candidate;
}

describe('active feed loader', () => {
  test('returns a validated remote feed', async () => {
    const candidate = validFeed();
    const loaded = await globalThis.ORBFeedLoader.loadActiveFeed('https://feed.example/latest.json', {
      validateFeed,
      fetchImpl: async () => ({ ok: true, async json() { return candidate; } }),
    });
    assert.equal(loaded, candidate);
  });

  test('network failure rejects without changing existing editor data', async () => {
    const current = { feed_name: 'Editor aktif', items: [{ id: 'tetap-ada' }] };
    await assert.rejects(
      () => globalThis.ORBFeedLoader.loadActiveFeed('https://feed.example/latest.json', {
        validateFeed,
        fetchImpl: async () => { throw new TypeError('network failed'); },
      }),
      (error) => error.code === 'network',
    );
    assert.deepEqual(current, { feed_name: 'Editor aktif', items: [{ id: 'tetap-ada' }] });
  });

  test('invalid JSON rejects before validation or replacement', async () => {
    let validated = false;
    await assert.rejects(
      () => globalThis.ORBFeedLoader.loadActiveFeed('https://feed.example/latest.json', {
        validateFeed() { validated = true; },
        fetchImpl: async () => ({ ok: true, async json() { throw new SyntaxError('bad json'); } }),
      }),
      (error) => error.code === 'json',
    );
    assert.equal(validated, false);
  });

  test('schema validation failure is reported distinctly', async () => {
    await assert.rejects(
      () => globalThis.ORBFeedLoader.loadActiveFeed('https://feed.example/latest.json', {
        validateFeed,
        fetchImpl: async () => ({ ok: true, async json() { return { items: 'invalid' }; } }),
      }),
      (error) => error.code === 'validation' && /struktur feed tidak valid/u.test(error.message),
    );
  });
});
