const loadReCaptcha = () => {
    if (document.querySelector('script[src*="recaptcha/api.js"]')) return;

    const script = document.createElement('script');
    script.async = true;
    script.defer = true;
    script.src = 'https://www.google.com/recaptcha/api.js';
    document.body.appendChild(script);
};

export default loadReCaptcha;
