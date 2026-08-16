const loadReCaptcha = (hl?: string | null) => {
    if (document.querySelector('script[src*="recaptcha/api.js"]')) return;

    const script = document.createElement('script');
    script.async = true;
    script.defer = true;
    script.src = hl ? `https://www.google.com/recaptcha/api.js?hl=${encodeURIComponent(hl)}` : 'https://www.google.com/recaptcha/api.js';
    document.body.appendChild(script);
};

export default loadReCaptcha;
