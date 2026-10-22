type Gtag = (...args: unknown[]) => void;

declare global {
  interface Window {
    dataLayer: unknown[][];
    gtag?: Gtag;
  }
}

export function isAnalyticsConfigured(measurementId: string | undefined): measurementId is string {
  return typeof measurementId === 'string' && /^G-[A-Z0-9]+$/.test(measurementId);
}

export function initializeAnalytics(measurementId: string | undefined) {
  if (!isAnalyticsConfigured(measurementId)) return;
  if (window.gtag) return;

  window.dataLayer = window.dataLayer ?? [];
  const gtag: Gtag = (...args: unknown[]) => window.dataLayer.push(args);
  window.gtag = gtag;
  gtag('js', new Date());
  gtag('config', measurementId);

  const script = document.createElement('script');
  script.async = true;
  script.src = `https://www.googletagmanager.com/gtag/js?id=${measurementId}`;
  document.head.append(script);
}
