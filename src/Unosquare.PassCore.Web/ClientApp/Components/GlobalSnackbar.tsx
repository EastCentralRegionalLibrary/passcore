import IconButton from '@mui/material/IconButton';
import Snackbar, { SnackbarOrigin } from '@mui/material/Snackbar';
import SnackbarContent from '@mui/material/SnackbarContent';
import Typography from '@mui/material/Typography';
import CheckCircle from '@mui/icons-material/CheckCircle';
import Close from '@mui/icons-material/Close';
import Error from '@mui/icons-material/Error';
import Info from '@mui/icons-material/Info';
import Warning from '@mui/icons-material/Warning';
import makeStyles from '@mui/styles/makeStyles';
import * as React from 'react';
import { Theme } from '@mui/material/styles';
import { SnackbarMessageType } from '../types/Components';

import { amber, blue, green, red } from '@mui/material/colors';

const useStyles = makeStyles(({ palette }: Theme) => ({
    closeIcon: {
        color: '#fff !important',
        fontSize: '20px  !important',
    },
    error: {
        backgroundColor: palette ? `${palette.error.main} !important` : `${red[600]} !important`,
        display: 'flex !important',
    },
    icon: {
        fontSize: '20px  !important',
        marginRight: '15px  !important',
    },
    iconMobile: {
        fontSize: '34px  !important',
        marginRight: '15px  !important',
    },
    info: {
        backgroundColor: palette ? `${palette.primary.main} !important` : `${blue[600]} !important`,
        display: 'flex !important',
    },
    success: {
        backgroundColor: `${green[600]} !important`,
        display: 'flex !important',
    },
    text: {
        alignItems: 'center',
        color: '#fff !important',
        display: 'inline-flex !important',
        fontSize: '18px !important',
    },
    textMobile: {
        color: '#fff !important',
        display: 'inline-flex !important',
        fontSize: '28px !important',
    },
    warning: {
        backgroundColor: `${amber[700]} !important`,
        display: 'flex !important',
    },
}));

export interface GlobalSnackbarProps {
    message: { messageText: string; messageType: SnackbarMessageType };
    milliSeconds: number;
    mobile: boolean;
}

export const GlobalSnackbar: React.FC<GlobalSnackbarProps> = ({
    message,
    milliSeconds = 2500,
    mobile = false,
}) => {
    const classes = useStyles({});
    const [open, setOpen] = React.useState(false);

    const getIconStyle = (): string => (mobile ? classes.iconMobile : classes.icon);

    const getIcon = (): JSX.Element => {
        switch (message.messageType) {
            case 'info':
                return <Info className={getIconStyle()} />;
            case 'warning':
                return <Warning className={getIconStyle()} />;
            case 'error':
                return <Error className={getIconStyle()} />;
            default:
                return <CheckCircle className={getIconStyle()} />;
        }
    };

    const getStyle = (): string => {
        switch (message.messageType) {
            case 'info':
                return classes.info;
            case 'warning':
                return classes.warning;
            case 'error':
                return classes.error;
            default:
                return classes.success;
        }
    };

    const getTextStyle = (): string => (mobile ? classes.textMobile : classes.text);
    const onClose = (): void => setOpen(false);

    React.useEffect(() => {
        if (message && message.messageText !== '') {
            setOpen(true);
            setTimeout(() => setOpen(false), milliSeconds);
        }
    }, [message]);

    const anchorOrigin: SnackbarOrigin = {
        horizontal: mobile ? 'center' : 'right',
        vertical: 'bottom',
    };

    return (
        <Snackbar anchorOrigin={anchorOrigin} className={getStyle()} open={open}>
            <SnackbarContent
                className={getStyle()}
                message={
                    <Typography className={getTextStyle()}>
                        {getIcon()} {message.messageText}
                    </Typography>
                }
                action={
                    !mobile && (
                        <IconButton onClick={onClose} size="large">
                            <Close className={classes.closeIcon} />
                        </IconButton>
                    )
                }
            />
        </Snackbar>
    );
};
