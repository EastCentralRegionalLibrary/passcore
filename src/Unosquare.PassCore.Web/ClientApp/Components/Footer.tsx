import Box from '@mui/material/Box';
import Stack from '@mui/material/Stack';
import Typography from '@mui/material/Typography';
import { appVersion } from '../version';
import mitLogo from 'url:../assets/images/License_icon-mit.svg.png';
import uslogo from 'url:../assets/images/logo.png';
import osiLogo from 'url:../assets/images/osi.png';
import passcoreLogo from 'url:../assets/images/passcore-logo.png';

export function Footer() {
    return (
        <Box component="footer" sx={{ mt: 5 }}>
            <Stack
                direction={{ xs: 'column', sm: 'row' }}
                spacing={2}
                sx={{
                    justifyContent: 'space-between',
                    alignItems: 'center',
                }}
            >
                <Box
                    component="img"
                    src={passcoreLogo}
                    sx={{
                        maxWidth: 125,
                        px: 2,
                    }}
                    alt="PassCore Logo"
                />
                <Stack direction="row" spacing={1} sx={{ alignItems: 'center' }}>
                    <Box component="img" src={osiLogo} sx={{ maxHeight: 30 }} alt="OSI Logo" />
                    <Box component="img" src={mitLogo} sx={{ maxHeight: 30 }} alt="MIT Logo" />
                    <Box component="img" src={uslogo} sx={{ maxHeight: 30 }} alt="US Logo" />
                </Stack>
            </Stack>
            <Stack
                spacing={0.5}
                sx={{
                    alignItems: 'center',
                    mt: 3,
                }}
            >
                <Typography variant="caption" sx={{ textAlign: 'center', color: 'text.secondary' }}>
                    Powered by PassCore {appVersion} - Open Source Initiative and MIT Licensed
                </Typography>
                <Typography variant="caption" sx={{ textAlign: 'center', color: 'text.secondary' }}>
                    Copyright © 2016-{new Date().getFullYear()} Unosquare
                </Typography>
            </Stack>
        </Box>
    );
}
