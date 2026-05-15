import Snackbar, { SnackbarOrigin } from '@mui/material/Snackbar';
import Alert from '@mui/material/Alert';
import { useState, useEffect } from 'react';
import { SnackbarMessageType } from '../types/Components';

export interface GlobalSnackbarProps {
    message: { messageText: string; messageType: SnackbarMessageType };
    milliSeconds?: number;
}

export function GlobalSnackbar({
    message,
    milliSeconds = 2500,
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
        horizontal: 'right',
        vertical: 'bottom',
    };

    return (
        <Snackbar data-testid="error-snackbar" anchorOrigin={anchorOrigin} open={open}>
            <Alert
                severity={message.messageType}
                onClose={() => setOpen(false)}
                variant="filled"
            >
                {message.messageText}
            </Alert>
        </Snackbar>
    );
}
