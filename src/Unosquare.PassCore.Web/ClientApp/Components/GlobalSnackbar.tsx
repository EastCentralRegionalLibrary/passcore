import Snackbar, { SnackbarOrigin } from '@mui/material/Snackbar';
import Alert from '@mui/material/Alert';
import { useState, useEffect } from 'react';
import { SnackbarMessageType } from '../types/Components';

export interface GlobalSnackbarProps {
    message: { messageText: string; messageType: SnackbarMessageType };
    milliSeconds: number;
    mobile: boolean;
}

const severityMap: Record<SnackbarMessageType, 'success' | 'error' | 'warning' | 'info'> = {
    success: 'success',
    error: 'error',
    warning: 'warning',
    info: 'info',
};

export function GlobalSnackbar({
    message,
    milliSeconds = 2500,
    mobile = false,
}: GlobalSnackbarProps) {
    const [open, setOpen] = useState(false);

    useEffect(() => {
        if (message?.messageText) {
            setOpen(true);
            const timer = setTimeout(() => setOpen(false), milliSeconds);
            return () => {
                clearTimeout(timer);
            };
        }
        return undefined;
    }, [message, milliSeconds]);

    const anchorOrigin: SnackbarOrigin = {
        horizontal: mobile ? 'center' : 'right',
        vertical: 'bottom',
    };

    return (
        <Snackbar anchorOrigin={anchorOrigin} open={open}>
            <Alert
                severity={severityMap[message.messageType]}
                onClose={mobile ? undefined : () => setOpen(false)}
                variant="filled"
                sx={{ fontSize: mobile ? '1.2rem' : undefined }}
            >
                {message.messageText}
            </Alert>
        </Snackbar>
    );
};
