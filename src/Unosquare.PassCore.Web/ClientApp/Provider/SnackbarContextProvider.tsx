import * as React from 'react';
import { SnackbarContainer } from '../Components/SnackbarContainer';
import { snackbarService } from '../Components/SnackbarService';
import { SnackbarContext } from './GlobalContext';
import { SnackbarMessageType } from '../types/Components';

interface ISnackbarProviderProps {
    children: React.ReactNode;
}

export const SnackbarContextProvider: React.FC<ISnackbarProviderProps> = ({ children }) => {
    const [providerValue] = React.useState({
        sendMessage: async (messageText: string, messageType: SnackbarMessageType = 'success') => {
            return snackbarService.showSnackbar(messageText, messageType);
        },
    });

    return (
        <SnackbarContext.Provider value={providerValue}>
            {children}
            <SnackbarContainer />
        </SnackbarContext.Provider>
    );
};
