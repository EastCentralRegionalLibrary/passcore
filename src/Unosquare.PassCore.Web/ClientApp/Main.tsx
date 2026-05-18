import Box from '@mui/material/Box';
import Typography from '@mui/material/Typography';
import { useEffect } from 'react';
import { LoadingIcon } from './Components/LoadingIcon';
import { useEffectWithLoading } from './Components/hooks/useEffectWithLoading';
import { EntryPoint } from './Components/EntryPoint';
import { loadReCaptcha } from './Components/GoogleReCaptcha';
import { GlobalContextProvider } from './Provider/GlobalContextProvider';
import { SnackbarContextProvider } from './Provider/SnackbarContextProvider';
import { resolveAppSettings } from './Utils/AppSettings';
import { IGlobalContext } from './types/Providers';

export function Main() {
    const [settings, isLoading, error] = useEffectWithLoading<IGlobalContext>(resolveAppSettings, {} as IGlobalContext, []);

    useEffect(() => {
        if (settings?.recaptcha?.siteKey && settings.recaptcha.siteKey !== '') {
            loadReCaptcha();
        }

        if (settings?.applicationTitle) {
            const titleElement = document.getElementById('title');
            if (titleElement) {
                titleElement.textContent = settings.applicationTitle;
            }
        }
    }, [settings]);

    if (isLoading) {
        return (
            <Box
                sx={{
                    display: 'flex',
                    flexDirection: 'column',
                    alignItems: 'center',
                    justifyContent: 'center',
                }}
            >
                <Box key="title" sx={{ mb: 2 }}>
                    <Typography variant="h3" sx={{ textAlign: 'center' }}>
                        Loading Passcore...
                    </Typography>
                </Box>
                <Box>
                    <LoadingIcon />
                </Box>
            </Box>
        );
    }

    if (error) {
        return (
            <Box sx={{ display: 'flex', justifyContent: 'center', alignItems: 'center', height: '100vh' }}>
                <Typography variant="h6" sx={{ color: 'error.main' }}>
                    Failed to load application settings. Be sure the settings file exists and file permissions are correct.
                </Typography>
            </Box>
        );
    }

    return (
        <GlobalContextProvider settings={settings}>
            <SnackbarContextProvider>
                <EntryPoint />
            </SnackbarContextProvider>
        </GlobalContextProvider>
    );
}