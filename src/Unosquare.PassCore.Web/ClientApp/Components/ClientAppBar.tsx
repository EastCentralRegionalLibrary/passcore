import AppBar from '@mui/material/AppBar';
import Box from '@mui/material/Box';
import IconButton from '@mui/material/IconButton';
import Tooltip from '@mui/material/Tooltip';
import Typography from '@mui/material/Typography';
import HelpIcon from '@mui/icons-material/Help';
import { use } from 'react';
import { GlobalContext } from '../Provider/GlobalContext';

export function ClientAppBar() {
    const { changePasswordForm, changePasswordTitle } = use(GlobalContext);
    const { helpText } = changePasswordForm;

    return (
        <AppBar
            position="fixed"
            elevation={0}
            sx={{ height: 64 }}
        >
            <Box
                sx={{
                    display: 'flex',
                    justifyContent: 'space-between',
                    alignItems: 'center',
                    height: 64,
                    width: '100%',
                    px: 3,
                }}
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
