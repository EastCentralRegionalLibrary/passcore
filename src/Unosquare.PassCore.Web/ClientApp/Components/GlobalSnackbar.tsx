import Snackbar, { SnackbarOrigin } from '@mui/material/Snackbar';
import Alert from '@mui/material/Alert';
import { SnackbarMessageType } from '../types/Components';

export interface GlobalSnackbarProps {
    open: boolean;
    message: { messageText: string; messageType: SnackbarMessageType };
    onClose: () => void;
    milliSeconds?: number;
}

export function GlobalSnackbar({
    open,
    message,
    onClose,
    milliSeconds = 5000,
}: GlobalSnackbarProps) {
    const anchorOrigin: SnackbarOrigin = {
        horizontal: 'right',
        vertical: 'bottom',
    };

    return (
        <Snackbar
            data-testid="snackbar-notification"
            anchorOrigin={anchorOrigin}
            open={open}
            autoHideDuration={milliSeconds}
            onClose={onClose}
        >
            <Alert
                severity={message.messageType}
                onClose={onClose}
                variant="filled"
            >
                {message.messageText}
            </Alert>
        </Snackbar>
    );
}
