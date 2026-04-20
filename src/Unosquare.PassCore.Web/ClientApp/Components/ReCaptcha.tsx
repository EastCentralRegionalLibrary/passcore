import Box from '@mui/material/Box';
import * as React from 'react';
import { GlobalContext } from '../Provider/GlobalContext';
import GoogleReCaptcha from './GoogleReCaptcha';

interface IRecaptchaProps {
    setToken: any;
    shouldReset: boolean;
}

export const ReCaptcha: React.FC<IRecaptchaProps> = ({ setToken, shouldReset }: IRecaptchaProps) => {
    // tslint:disable-next-line
    let captchaRef: any;

    const { siteKey } = React.useContext(GlobalContext).recaptcha;

    React.useEffect(() => {
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
