import IconButton from '@mui/material/IconButton';
import Snackbar from '@mui/material/Snackbar';
import Close from '@mui/icons-material/Close';
import * as React from 'react';
import { styled } from '@mui/material/styles';
import { SnackbarMessageType } from '../types/Components';
import { Alert, AlertProps } from '@mui/material';
import CheckCircleOutlineIcon from '@mui/icons-material/CheckCircleOutline';
import ErrorOutlineIcon from '@mui/icons-material/ErrorOutline';
import InfoOutlinedIcon from '@mui/icons-material/InfoOutlined';
import WarningOutlinedIcon from '@mui/icons-material/WarningOutlined';

interface GlobalSnackbarProps {
    message: { messageText: string; messageType: SnackbarMessageType };
    milliSeconds: number;
    mobile: boolean;
}

const StyledAlert = styled(Alert)(({ theme }) => ({
    '& .MuiAlert-icon': {
        fontSize: '20px',
        marginRight: theme.spacing(2),
    },
    '& .MuiAlert-message': {
        fontSize: '18px',
        color: theme.palette.common.white,
        display: 'inline-flex',
        alignItems: 'center',
    },
    [theme.breakpoints.down('sm')]: {
        '& .MuiAlert-icon': {
            fontSize: '34px',
        },
        '& .MuiAlert-message': {
            fontSize: '28px',
        },
    },
}));

const GlobalSnackbarComponent: React.FC<GlobalSnackbarProps> = ({
    message,
    milliSeconds = 2500,
    mobile = false,
}) => {
    const [open, setOpen] = React.useState(false);

    React.useEffect(() => {
        if (message && message.messageText !== '') {
            setOpen(true);
            const timer = setTimeout(() => setOpen(false), milliSeconds);
            return () => clearTimeout(timer);
        }
        return undefined;
    }, [message, milliSeconds]);

    const severityMap: Record<SnackbarMessageType, AlertProps['severity']> = {
        info: 'info',
        warning: 'warning',
        error: 'error',
        success: 'success',
    };

    const iconMap: Record<SnackbarMessageType, JSX.Element> = {
        info: <InfoOutlinedIcon />,
        warning: <WarningOutlinedIcon />,
        error: <ErrorOutlineIcon />,
        success: <CheckCircleOutlineIcon />,
    };

    const getSeverity = (): AlertProps['severity'] => severityMap[message.messageType] || 'success';

    const getIcon = (): JSX.Element => iconMap[message.messageType] || <CheckCircleOutlineIcon />;

    const handleClose = (): void => setOpen(false);

    return (
        <Snackbar
            anchorOrigin={{ horizontal: mobile ? 'center' : 'right', vertical: 'bottom' }}
            open={open}
        >
            <StyledAlert
                severity={getSeverity()}
                icon={getIcon()}
                action={
                    !mobile && (
                        <IconButton onClick={handleClose} size="large" color="inherit">
                            <Close />
                        </IconButton>
                    )
                }
            >
                {message.messageText}
            </StyledAlert>
        </Snackbar>
    );
};

const GlobalSnackbar = React.memo(GlobalSnackbarComponent);
GlobalSnackbar.displayName = 'GlobalSnackbar';

export { GlobalSnackbar };