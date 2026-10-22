import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';

const SITE = new URL('../', import.meta.url);
const pages = [
  { path: 'index.html', route: '' },
  { path: 'evidence/index.html', route: 'evidence/' },
  { path: 'engines/index.html', route: 'engines/' },
  { path: 'integrate/index.html', route: 'integrate/' },
  { path: 'guidance/index.html', route: 'guidance/' },
];

test('all published pages have unique SEO and share metadata with a valid canonical', () => {
  const titles = new Set<string>();
  const descriptions = new Set<string>();

  for (const page of pages) {
    const html = readFileSync(new URL(page.path, SITE), 'utf8');
    const title = html.match(/<title>(.*?)<\/title>/)?.[1];
    const description = html.match(/<meta name="description" content="(.*?)"/)?.[1];
    const canonical = html.match(/<link rel="canonical" href="(.*?)"/)?.[1];

    assert.ok(title, `${page.path} needs a title`);
    assert.ok(description, `${page.path} needs a description`);
    assert.equal(canonical, `https://okhp3.github.io/skillz-shield/${page.route}`);
    assert.ok(!titles.has(title), `${page.path} title should be unique`);
    assert.ok(!descriptions.has(description), `${page.path} description should be unique`);
    titles.add(title);
    descriptions.add(description);

    assert.match(html, /<meta name="robots" content="index,follow,max-image-preview:large"/);
    assert.match(html, /<meta property="og:type" content="website"/);
    assert.match(html, /<meta property="og:title"/);
    assert.match(html, /<meta property="og:description"/);
    assert.match(html, /<meta property="og:url"/);
    assert.match(html, /<meta property="og:image" content="https:\/\/okhp3\.github\.io\/skillz-shield\/shield-social\.png"/);
    assert.match(html, /<meta property="og:image:width" content="1200"/);
    assert.match(html, /<meta property="og:image:height" content="630"/);
    assert.match(html, /<meta name="twitter:card" content="summary_large_image"/);
    assert.match(html, /<meta name="twitter:image"/);
    assert.match(html, /favicon\.svg/);
    assert.match(html, /favicon\.ico/);
    assert.match(html, /apple-touch-icon\.png/);
    assert.match(html, /safari-pinned-tab\.svg/);
    assert.match(html, /site\.webmanifest/);
    assert.match(html, /src\/main\.tsx/);
  }
});

test('analytics requires explicit production configuration without a copied property', () => {
  const analytics = readFileSync(new URL('src/analytics.ts', SITE), 'utf8');
  const main = readFileSync(new URL('src/main.tsx', SITE), 'utf8');
  assert.doesNotMatch(analytics, /G-VJ1BKXS27H/);
  assert.match(analytics, /gtag\('config', measurementId\)/);
  assert.match(analytics, /googletagmanager\.com\/gtag\/js/);
  assert.match(main, /import\.meta\.env\.PROD/);
  assert.match(main, /initializeAnalytics\(import\.meta\.env\.VITE_GA_MEASUREMENT_ID\)/);
});

test('robots and sitemap enumerate the public GitHub Pages routes', () => {
  const robots = readFileSync(new URL('public/robots.txt', SITE), 'utf8');
  const sitemap = readFileSync(new URL('public/sitemap.xml', SITE), 'utf8');
  assert.match(robots, /Allow: \//);
  assert.match(robots, /https:\/\/okhp3\.github\.io\/skillz-shield\/sitemap\.xml/);
  for (const page of pages) {
    assert.ok(sitemap.includes(`https://okhp3.github.io/skillz-shield/${page.route}`));
  }
});

test('social, avatar, and pinned-app PNGs use their declared dimensions', () => {
  const dimensions = [
    ['public/shield-social.png', 1200, 630],
    ['public/shield-avatar.png', 512, 512],
    ['public/favicon-16.png', 16, 16],
    ['public/favicon-32.png', 32, 32],
    ['public/apple-touch-icon.png', 180, 180],
    ['public/icon-192.png', 192, 192],
    ['public/icon-512.png', 512, 512],
  ] as const;
  for (const [path, width, height] of dimensions) {
    const png = readFileSync(new URL(path, SITE));
    assert.equal(png.toString('ascii', 1, 4), 'PNG');
    assert.equal(png.readUInt32BE(16), width, `${path} width`);
    assert.equal(png.readUInt32BE(20), height, `${path} height`);
  }
});
