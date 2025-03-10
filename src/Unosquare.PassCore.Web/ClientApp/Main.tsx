import Box from '@mui/material/Box';
import Typography from '@mui/material/Typography/Typography';
import * as React from 'react';
import { LoadingIcon } from './Components/LoadingIcon';
import { useEffectWithLoading } from './Components/hooks/useEffectWithLoading';
import { EntryPoint } from './Components/EntryPoint';
import { loadReCaptcha } from './Components/GoogleReCaptcha';
import { GlobalContextProvider } from './Provider/GlobalContextProvider';
import { SnackbarContextProvider } from './Provider/SnackbarContextProvider';
import { resolveAppSettings } from './Utils/AppSettings';
import { IGlobalContext } from './types/Providers';

export const Main: React.FC = () => {
    const [settings, isLoading] = useEffectWithLoading<IGlobalContext>(resolveAppSettings, {} as IGlobalContext, []);

    React.useEffect(() => {
        if (settings && typeof settings !== 'boolean' && settings.recaptcha?.siteKey) {
            if (settings.recaptcha.siteKey !== '') {
                loadReCaptcha();
            }
        }
    }, [settings]);

    if (isLoading) {
        return (
            <Box
                display="flex"
                flexDirection="column"
                alignItems="center"
                justifyContent="center"
                // height="100vh" // Optional: Make it take up the full viewport height
            >
                <Box key="title" marginBottom={2}> {/* Add some spacing */}
                    <Typography variant="h3" align="center">
                        Loading Passcore...
                    </Typography>
                </Box>
                <Box>
                    <LoadingIcon />
                </Box>
            </Box>
        );
    }

    if (settings && typeof settings !== 'boolean' && settings.applicationTitle) {
        const titleElement = document.getElementById('title');
        if (titleElement) {
            titleElement.innerHTML = settings.applicationTitle;
        }
    }

    // Type guard before passing to GlobalContextProvider
    if (typeof settings !== 'boolean') {
        return (
            <GlobalContextProvider settings={settings}>
                <SnackbarContextProvider>
                    <EntryPoint />
                </SnackbarContextProvider>
            </GlobalContextProvider>
        );
    }

    // Handle the boolean case (e.g., render an error message)
    return (
        <Box display="flex" justifyContent="center" alignItems="center" height="100vh">
            <Typography variant="h6" color="error">
                Failed to load application settings. Be sure the settings file exists and file permissions are correct.
            </Typography>
        </Box>
    );
};