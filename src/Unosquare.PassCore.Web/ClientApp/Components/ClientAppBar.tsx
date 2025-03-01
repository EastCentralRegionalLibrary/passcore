import AppBar from '@mui/material/AppBar/AppBar';
import Grid from '@mui/material/Grid/Grid';
import Tooltip from '@mui/material/Tooltip/Tooltip';
import Typography from '@mui/material/Typography/Typography';
import HelpIcon from '@mui/icons-material/Help';
import * as React from 'react';
import { GlobalContext } from '../Provider/GlobalContext';

export const ClientAppBar: React.FunctionComponent<any> = () => {
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
            <Grid
                container
                style={{ height: '64px', width: '100%' }}
                direction="row"
                justifyContent="space-between"
                alignItems="center"
            >
                <Typography
                    variant="h6"
                    color="secondary"
                    style={{
                        paddingLeft: '1.5%',
                        width: '70%',
                    }}
                >
                    {changePasswordTitle}
                </Typography>
                <Tooltip title={helpText} placement="left">
                    <HelpIcon color="secondary" style={{ paddingRight: '1%' }} />
                </Tooltip>
            </Grid>
        </AppBar>
    );
};
