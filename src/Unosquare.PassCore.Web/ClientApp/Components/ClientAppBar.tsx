import AppBar from '@mui/material/AppBar';
import IconButton from '@mui/material/IconButton';
import Toolbar from '@mui/material/Toolbar';
import Tooltip from '@mui/material/Tooltip';
import Typography from '@mui/material/Typography';
import HelpIcon from '@mui/icons-material/Help';
import { use } from 'react';
import { GlobalContext } from '../Provider/GlobalContext';

export function ClientAppBar() {
    const context = use(GlobalContext)!;
    const changePasswordForm = context?.changePasswordForm;
    const changePasswordTitle = context?.changePasswordTitle || '';
    const helpText = changePasswordForm?.helpText || '';

    return (
        <AppBar
            position="fixed"
            elevation={0}
            sx={{
                zIndex: (theme) => theme.zIndex.appBar,
            }}
        >
            <Toolbar
                sx={{
                    justifyContent: 'space-between',
                    px: { xs: 2, sm: 3 },
                }}
            >
                <Typography
                    variant="h6"
                    noWrap
                    component="div"
                    sx={{
                        flexGrow: 1,
                        color: 'secondary.main',
                        overflow: 'hidden',
                        textOverflow: 'ellipsis',
                    }}
                >
                    {changePasswordTitle}
                </Typography>

                {helpText ? (
                    <Tooltip title={helpText} placement="left" arrow>
                        <IconButton color="secondary" size="large" edge="end">
                            <HelpIcon />
                        </IconButton>
                    </Tooltip>
                ) : (
                    <IconButton color="secondary" size="large" edge="end" disabled>
                        <HelpIcon sx={{ opacity: 0.5 }} />
                    </IconButton>
                )}
            </Toolbar>
        </AppBar>
    );
}
