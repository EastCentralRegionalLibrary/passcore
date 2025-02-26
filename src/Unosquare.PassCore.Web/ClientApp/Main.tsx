import Grid from '@mui/material/Grid/Grid';
import Typography from '@mui/material/Typography/Typography';
import * as React from 'react';
import { LoadingIcon } from './Components/LoadingIcon';
import { useEffectWithLoading } from './Components/hooks/useEffectWithLoading';
import { EntryPoint } from './Components/EntryPoint';
import { loadReCaptcha } from './Components/GoogleReCaptcha';
import { GlobalContextProvider } from './Provider/GlobalContextProvider';
import { SnackbarContextProvider } from './Provider/SnackbarContextProvider';
import { resolveAppSettings } from './Utils/AppSettings';

export const Main: React.FunctionComponent<any> = () => {
    const [settings, isLoading] = useEffectWithLoading(resolveAppSettings, {}, []);

    React.useEffect(() => {
        if (settings && settings.recaptcha) {
            if (settings.recaptcha.siteKey !== '') {
                loadReCaptcha();
            }
        }
    }, [settings]);

    if (isLoading) {
        return (
            <Grid container alignItems="center" direction="column" justifyContent="center">
                <Grid item key="title">
                    <Typography variant="h3" align="center">
                        Loading Passcore...
                    </Typography>
                </Grid>
                <Grid item>
                    <LoadingIcon />
                </Grid>
            </Grid>
        );
    }

    document.getElementById('title').innerHTML = settings.applicationTitle;

    return (
        <GlobalContextProvider settings={settings}>
            <SnackbarContextProvider>
                <EntryPoint />
            </SnackbarContextProvider>
        </GlobalContextProvider>
    );
};
