import test from 'node:test';
import assert from 'node:assert/strict';
import { initializeAnalytics } from '../src/analytics.ts';

test('analytics is inert without a valid explicit ID and initializes only once', () => {
  const appended: { async?: boolean; src?: string }[] = [];
  const browser: { dataLayer?: unknown[][]; gtag?: unknown } = {};
  const originals = ['window', 'document'].map(key => Object.getOwnPropertyDescriptor(globalThis, key));
  Object.defineProperty(globalThis, 'window', { configurable: true, value: browser });
  Object.defineProperty(globalThis, 'document', { configurable: true, value: {
    createElement: () => ({}), head: { append: (script: { src?: string }) => appended.push(script) },
  } });
  try {
    for (const id of [undefined, '', 'invalid', 'G-X?injected=true']) initializeAnalytics(id);
    assert.equal(appended.length, 0);
    assert.equal(browser.gtag, undefined);
    initializeAnalytics('G-SHIELDTEST');
    initializeAnalytics('G-SHIELDTEST');
    assert.equal(appended.length, 1);
    assert.equal(appended[0].src, 'https://www.googletagmanager.com/gtag/js?id=G-SHIELDTEST');
    assert.deepEqual(browser.dataLayer?.[1], ['config', 'G-SHIELDTEST']);
  } finally {
    ['window', 'document'].forEach((key, index) => {
      const descriptor = originals[index];
      if (descriptor) Object.defineProperty(globalThis, key, descriptor);
      else Reflect.deleteProperty(globalThis, key);
    });
  }
});
