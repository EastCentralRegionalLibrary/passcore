import { useMemo, type ReactNode } from 'react';
import { SnackbarContainer } from '../Components/SnackbarContainer';
import { snackbarService } from '../Components/SnackbarService';
import { SnackbarContext } from './GlobalContext';
import { SnackbarMessageType } from '../types/Components';

interface ISnackbarProviderProps {
    children: ReactNode;
}

export function SnackbarContextProvider({ children }: ISnackbarProviderProps) {
    const providerValue = useMemo(() => ({
        sendMessage: (messageText: string, messageType: SnackbarMessageType = 'success') => {
            snackbarService.showSnackbar(messageText, messageType);
        },
    }), []);

    return (
        <SnackbarContext.Provider value={providerValue}>
            {children}
            <SnackbarContainer />
        </SnackbarContext.Provider>
    );
}
