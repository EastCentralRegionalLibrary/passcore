import { useMemo, useState, useCallback, type ReactNode } from 'react';
import { GlobalSnackbar } from '../Components/GlobalSnackbar';
import { SnackbarContext } from './GlobalContext';
import { SnackbarMessageType } from '../types/Components';

interface ISnackbarProviderProps {
    children: ReactNode;
}

interface SnackbarState {
    messageText: string;
    messageType: SnackbarMessageType;
    open: boolean;
    key: number;
}

export function SnackbarContextProvider({ children }: ISnackbarProviderProps) {
    const [snackbar, setSnackbar] = useState<SnackbarState>({
        messageText: '',
        messageType: 'success',
        open: false,
        key: 0,
    });

    const sendMessage = useCallback((messageText: string, messageType: SnackbarMessageType = 'success') => {
        setSnackbar((prev) => ({
            messageText,
            messageType,
            open: true,
            key: prev.key + 1,
        }));
    }, []);

    const handleClose = useCallback(() => {
        setSnackbar((prev) => ({
            ...prev,
            open: false,
        }));
    }, []);

    const providerValue = useMemo(() => ({
        sendMessage,
    }), [sendMessage]);

    return (
        <SnackbarContext.Provider value={providerValue}>
            {children}
            <GlobalSnackbar
                key={snackbar.key}
                open={snackbar.open}
                message={{ messageText: snackbar.messageText, messageType: snackbar.messageType }}
                onClose={handleClose}
            />
        </SnackbarContext.Provider>
    );
}
