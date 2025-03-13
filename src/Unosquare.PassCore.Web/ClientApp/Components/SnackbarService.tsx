import { useState, useCallback } from 'react';
import { SnackbarMessageType } from '../types/Components';

export interface Snackbar {
    message: { messageText: string; messageType: SnackbarMessageType };
    milliSeconds?: number;
    isMobile: boolean;
}

export function useSnackbarService() {
    const [snackbar, setSnackbar] = useState<Snackbar>({
        isMobile: false,
        message: { messageText: '', messageType: 'success' },
    });

    const showSnackbar = useCallback(
        (message: string, type: SnackbarMessageType = 'success', milliSeconds = 5000) => {
            setSnackbar({
                isMobile: false,
                message: {
                    messageText: message,
                    messageType: type,
                },
                milliSeconds,
            });
        },
        [setSnackbar],
    );

    return { snackbar, showSnackbar };
}

export default useSnackbarService;
