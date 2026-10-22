type Gtag = (...args: unknown[]) => void;

declare global {
  interface Window {
    dataLayer: unknown[][];
    gtag?: Gtag;
  }
}

export function initializeAnalytics(measurementId: string | undefined) {
  if (!measurementId || !/^G-[A-Z0-9]+$/.test(measurementId)) return;
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
