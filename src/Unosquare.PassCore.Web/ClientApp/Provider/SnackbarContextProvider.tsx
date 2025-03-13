import * as React from 'react';
import { SnackbarContainer } from '../Components/SnackbarContainer';
import { SnackbarContext } from './GlobalContext';
import { SnackbarMessageType } from '../types/Components';
import useSnackbarService from '../Components/SnackbarService'; // Import the hook

interface ISnackbarProviderProps {
    children: React.ReactNode;
}

export const SnackbarContextProvider: React.FC<ISnackbarProviderProps> = ({ children }) => {
    const { snackbar, showSnackbar } = useSnackbarService(); // Get snackbar state

    const [providerValue] = React.useState({
        sendMessage: async (messageText: string, messageType: SnackbarMessageType = 'success') => {
            return showSnackbar(messageText, messageType);
        },
    });

    return (
        <SnackbarContext.Provider value={providerValue}>
            {children}
            <SnackbarContainer snackbar={snackbar} /> {/* Pass snackbar state */}
        </SnackbarContext.Provider>
    );
};
