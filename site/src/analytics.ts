const GA_MEASUREMENT_ID = 'G-VJ1BKXS27H';

type Gtag = (...args: unknown[]) => void;

declare global {
  interface Window {
    dataLayer: unknown[][];
    gtag?: Gtag;
  }
}

export function initializeAnalytics() {
  if (!/^G-[A-Z0-9]+$/.test(GA_MEASUREMENT_ID)) return;
  if (window.gtag) return;

  window.dataLayer = window.dataLayer ?? [];
  const gtag: Gtag = (...args: unknown[]) => window.dataLayer.push(args);
  window.gtag = gtag;
  gtag('js', new Date());
  gtag('config', GA_MEASUREMENT_ID);

  const script = document.createElement('script');
  script.async = true;
  script.src = `https://www.googletagmanager.com/gtag/js?id=${GA_MEASUREMENT_ID}`;
  document.head.append(script);
}
