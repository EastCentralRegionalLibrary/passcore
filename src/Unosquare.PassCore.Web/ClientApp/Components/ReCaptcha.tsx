import Box from '@mui/material/Box';
import { use, useEffect } from 'react';
import { GlobalContext } from '../Provider/GlobalContext';
import GoogleReCaptcha from './GoogleReCaptcha';

interface IRecaptchaProps {
    setToken: any;
    shouldReset: boolean;
}

export function ReCaptcha({ setToken, shouldReset }: IRecaptchaProps) {
    // tslint:disable-next-line
    let captchaRef: any;

    const { siteKey } = use(GlobalContext).recaptcha;

    useEffect(() => {
        if (captchaRef) {
            captchaRef.reset();
        }
    }, [shouldReset]);

    const onLoadRecaptcha = () => {
        if (captchaRef) {
            captchaRef.reset();
        }
    };

    const verifyCallback = (recaptchaToken: any) => setToken(recaptchaToken);

    return (
        <Box sx={{ display: 'flex', justifyContent: 'flex-end', mt: '25px' }}>
            <GoogleReCaptcha
                ref={(el: any) => {
                    captchaRef = el;
                }}
                size="normal"
                render="explicit"
                sitekey={siteKey}
                onloadCallback={onLoadRecaptcha}
                onSuccess={verifyCallback}
            />
        </Box>
    );
};
