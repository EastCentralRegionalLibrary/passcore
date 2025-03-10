import * as React from 'react';
import { GlobalContext } from './GlobalContext';
import { IGlobalContext } from '../types/Providers';

interface IGlobalContextProviderProps {
    children: React.ReactNode;
    settings: IGlobalContext;
}

export const GlobalContextProvider: React.FC<IGlobalContextProviderProps> = ({
    children,
    settings,
}: IGlobalContextProviderProps) => {
    const [getProviderValue] = React.useState<IGlobalContext>({ ...settings });

    return (
        <GlobalContext.Provider value={getProviderValue}>
            {children}
        </GlobalContext.Provider>
    );
};