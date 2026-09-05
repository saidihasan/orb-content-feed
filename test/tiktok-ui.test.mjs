import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { before, describe, test } from 'node:test';

const PRODUCTION_ORIGIN = 'https://orb-content-feed.saidihasan.workers.dev';
let generatorSource;
let indexSource;
let integrationSource;

function functionSource(source, name, nextName) {
  const start = source.indexOf(`function ${name}(`);
  const end = source.indexOf(`function ${nextName}(`, start);
  assert.notEqual(start, -1, `${name} is missing`);
  assert.notEqual(end, -1, `${nextName} is missing after ${name}`);
  return source.slice(start, end).trim();
}

function createTikTokInfo() {
  const source = functionSource(generatorSource, 'tiktokInfo', 'updateTypes');
  return Function(
    'TIKTOK_URL_MAX_LENGTH',
    'PRODUCTION_ORIGIN',
    `'use strict'; ${source}; return tiktokInfo;`,
  )(2048, PRODUCTION_ORIGIN);
}

before(async () => {
  [generatorSource, indexSource, integrationSource] = await Promise.all([
    readFile(new URL('../public/generator.html', import.meta.url), 'utf8'),
    readFile(new URL('../public/index.html', import.meta.url), 'utf8'),
    readFile(new URL('../public/website-integration.html', import.meta.url), 'utf8'),
  ]);
});

describe('TikTok generator support', () => {
  test('recognizes canonical and short URLs and creates a relative Worker thumbnail URL', () => {
    const tiktokInfo = createTikTokInfo();
    const canonical = 'https://www.tiktok.com/@orb.banten/video/1234567890123456789';
    assert.equal(
      tiktokInfo(canonical).thumbnail,
      `api/tiktok-thumbnail?url=${encodeURIComponent(canonical)}`,
    );
    assert.ok(tiktokInfo('https://vm.tiktok.com/ZMexample/'));
    assert.ok(tiktokInfo('https://vt.tiktok.com/ZMexample/'));
  });

  test('rejects fake TikTok domains, non-HTTPS URLs, invalid paths, and long URLs', () => {
    const tiktokInfo = createTikTokInfo();
    for (const value of [
      'https://tiktok.com.evil.example/@orb/video/1234567890123456789',
      'http://www.tiktok.com/@orb/video/1234567890123456789',
      'https://www.tiktok.com/@orb/photo/1234567890123456789',
      `https://www.tiktok.com/@orb/video/${'1'.repeat(2050)}`,
    ]) assert.equal(tiktokInfo(value), null, value);
  });

  test('automatic URL detection does not replace a manually edited thumbnail', () => {
    const tiktokInfoSource = functionSource(generatorSource, 'tiktokInfo', 'updateTypes');
    const detectUrlSource = functionSource(generatorSource, 'detectUrl', 'slugify');
    const detect = Function(
      'TIKTOK_URL_MAX_LENGTH',
      'PRODUCTION_ORIGIN',
      `'use strict'; ${tiktokInfoSource}; return (state) => {
        const urlInput={value:state.url};
        const thumbnail={value:state.thumbnail};
        const platform={value:'instagram'};
        const type={value:'post'};
        let lastAutoThumbnail=state.lastAutoThumbnail || '';
        const youtubeInfo=()=>null;
        const instagramInfo=()=>null;
        const updateTypes=(selected)=>{state.selectedType=selected;};
        ${detectUrlSource}
        detectUrl();
        return {thumbnail:thumbnail.value,platform:platform.value,type:type.value,lastAutoThumbnail};
      };`,
    )(2048, PRODUCTION_ORIGIN);
    const url = 'https://www.tiktok.com/@orb.banten/video/1234567890123456789';
    const automatic = detect({ url, thumbnail: '' });
    assert.equal(automatic.platform, 'tiktok');
    assert.equal(automatic.type, 'video');
    assert.match(automatic.thumbnail, /^api\/tiktok-thumbnail\?url=/u);

    const manual = detect({ url, thumbnail: 'https://images.example/manual.jpg' });
    assert.equal(manual.thumbnail, 'https://images.example/manual.jpg');
  });
});

describe('TikTok public display support', () => {
  test('diagnosis and integration validators accept only legitimate TikTok URLs', () => {
    for (const [source, nextName] of [[indexSource, 'validItem'], [integrationSource, 'validItem']]) {
      const validatorSource = functionSource(source, 'validTikTokUrl', nextName);
      const validTikTokUrl = Function(`'use strict'; ${validatorSource}; return validTikTokUrl;`)();
      assert.equal(validTikTokUrl('https://www.tiktok.com/@orb/video/1234567890123456789'), true);
      assert.equal(validTikTokUrl('https://vm.tiktok.com/ZMexample/'), true);
      assert.equal(validTikTokUrl('https://tiktok.com.evil.example/@orb/video/1234567890123456789'), false);
      assert.equal(validTikTokUrl('http://www.tiktok.com/@orb/video/1234567890123456789'), false);
    }
  });

  test('all user-facing surfaces use the TikTok Video label', () => {
    for (const source of [generatorSource, indexSource, integrationSource]) {
      assert.match(source, /tiktok:\{video:'TikTok Video'\}/u);
    }
  });
});
