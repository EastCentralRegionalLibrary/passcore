import AppBar from '@mui/material/AppBar/AppBar';
import Box from '@mui/material/Box';
import IconButton from '@mui/material/IconButton';
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
            elevation={0}
            sx={{ height: 64 }}
        >
            <Box
                display="flex"
                justifyContent="space-between"
                alignItems="center"
                sx={{ height: 64 }}
                width="100%"
                padding="0 24px"
            >
                <Typography
                    variant="h6"
                    color="secondary"
                    sx={{ flexGrow: 1 }}
                >
                    {changePasswordTitle}
                </Typography>

                {helpText ? (
                    <Tooltip title={helpText} placement="left" arrow>
                        <IconButton color="secondary" size="large">
                            <HelpIcon />
                        </IconButton>
                    </Tooltip>
                ) : (
                    <IconButton color="secondary" size="large" disabled>
                        <HelpIcon sx={{ opacity: 0.5 }} />
                    </IconButton>
                )}
            </Box>
        </AppBar>
    );
};
