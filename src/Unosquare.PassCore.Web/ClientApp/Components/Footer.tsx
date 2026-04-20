import Box from '@mui/material/Box';
import Typography from '@mui/material/Typography/Typography';
import * as React from 'react';
import { appVersion } from '../version';
import mitLogo from 'url:../assets/images/License_icon-mit.svg.png';
import uslogo from 'url:../assets/images/logo.png';
import osiLogo from 'url:../assets/images/osi.png';
import passcoreLogo from 'url:../assets/images/passcore-logo.png';

export const Footer: React.FC = () => (
    <Box
        marginTop="40px"
        width="650px"
    >
        <Box
            display="flex"
            justifyContent="space-between"
            alignItems="center"
        >
            <Box>
                <img src={passcoreLogo.default || passcoreLogo} style={{ marginLeft: '15px', maxWidth: '125px' }} alt="PassCore Logo" />
            </Box>
            <Box>
                <img src={osiLogo.default || osiLogo} style={{ margin: '0 10px 0 40px', maxHeight: '30px' }} alt="OSI Logo" />
                <img src={mitLogo.default || mitLogo} style={{ marginRight: '10px', maxHeight: '30px' }} alt="MIT Logo" />
                <img src={uslogo.default || uslogo} style={{ maxHeight: '30px' }} alt="US Logo" />
            </Box>
        </Box>
        <Box
            display="flex"
            flexDirection="column"
            alignItems="center"
            justifyContent="space-evenly"
            marginTop={2}
        >
            <Typography align="center" variant="caption">
                Powered by PassCore {appVersion} - Open Source Initiative and MIT Licensed
            </Typography>
            <Typography align="center" variant="caption">
                Copyright © 2016-{new Date().getFullYear()} Unosquare
            </Typography>
        </Box>
    </Box>
);