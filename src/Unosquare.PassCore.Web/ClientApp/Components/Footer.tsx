import Box from '@mui/material/Box';
import Typography from '@mui/material/Typography';
import { appVersion } from '../version';
import mitLogo from 'url:../assets/images/License_icon-mit.svg.png';
import uslogo from 'url:../assets/images/logo.png';
import osiLogo from 'url:../assets/images/osi.png';
import passcoreLogo from 'url:../assets/images/passcore-logo.png';

export function Footer() {
    return (
    <Box sx={{ mt: '40px' }}>
        <Box
            sx={{
                display: 'flex',
                justifyContent: 'space-between',
                alignItems: 'center',
            }}
        >
            <Box>
                <img src={passcoreLogo} style={{ marginLeft: '15px', maxWidth: '125px' }} alt="PassCore Logo" />
            </Box>
            <Box>
                <img src={osiLogo} style={{ margin: '0 10px 0 40px', maxHeight: '30px' }} alt="OSI Logo" />
                <img src={mitLogo} style={{ marginRight: '10px', maxHeight: '30px' }} alt="MIT Logo" />
                <img src={uslogo} style={{ maxHeight: '30px' }} alt="US Logo" />
            </Box>
        </Box>
        <Box
            sx={{
                display: 'flex',
                flexDirection: 'column',
                alignItems: 'center',
                justifyContent: 'space-evenly',
                mt: 2,
            }}
        >
            <Typography variant="caption" sx={{ textAlign: 'center' }}>
                Powered by PassCore {appVersion} - Open Source Initiative and MIT Licensed
            </Typography>
            <Typography variant="caption" sx={{ textAlign: 'center' }}>
                Copyright © 2016-{new Date().getFullYear()} Unosquare
            </Typography>
        </Box>
    </Box>
    );
}
