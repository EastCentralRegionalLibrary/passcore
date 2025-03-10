import AppBar from '@mui/material/AppBar/AppBar';
import Box from '@mui/material/Box';
import Tooltip from '@mui/material/Tooltip/Tooltip';
import Typography from '@mui/material/Typography/Typography';
import HelpIcon from '@mui/icons-material/Help';
import * as React from 'react';
import { GlobalContext } from '../Provider/GlobalContext';

export const ClientAppBar: React.FC = () => {
    const { changePasswordForm, changePasswordTitle } = React.useContext(GlobalContext);
    const { helpText } = changePasswordForm;

    return (
        <AppBar
            position="fixed"
            style={{
                backgroundColor: '#304FF3',
                height: '64px',
            }}
            elevation={0}
        >
            <Box
                display="flex"
                justifyContent="space-between"
                alignItems="center"
                height="64px"
                width="100%"
                padding="0 1.5%" // Add padding to the sides
            >
                <Typography
                    variant="h6"
                    color="secondary"
                    style={{
                        width: '70%',
                    }}
                >
                    {changePasswordTitle}
                </Typography>
                <Tooltip title={helpText} placement="left">
                    <HelpIcon color="secondary" />
                </Tooltip>
            </Box>
        </AppBar>
    );
};
