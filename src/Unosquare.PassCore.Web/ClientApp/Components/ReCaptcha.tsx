import Box from '@mui/material/Box';
import { use, useEffect, useRef } from 'react';
import { GlobalContext } from '../Provider/GlobalContext';
import GoogleReCaptcha from './GoogleReCaptcha';

interface IRecaptchaProps {
    setToken: (token: string) => void;
    shouldReset: boolean;
}

export function ReCaptcha({ setToken, shouldReset }: IRecaptchaProps) {
    const captchaRef = useRef<InstanceType<typeof GoogleReCaptcha> | null>(null);

    const { siteKey } = use(GlobalContext)!.recaptcha;

    useEffect(() => {
        if (captchaRef.current) {
            captchaRef.current.reset();
        }
    }, [shouldReset]);

    const onLoadRecaptcha = () => {
        if (captchaRef.current) {
            captchaRef.current.reset();
        }
    };

    const verifyCallback = (recaptchaToken: string) => setToken(recaptchaToken);

    return (
        <Box sx={{ display: 'flex', justifyContent: 'flex-end', mt: '25px' }}>
            <GoogleReCaptcha
                ref={(el) => {
                    captchaRef.current = el;
                }}
                size="normal"
                render="explicit"
                sitekey={siteKey}
                onloadCallback={onLoadRecaptcha}
                onSuccess={verifyCallback}
            />
        </Box>
    );
}
