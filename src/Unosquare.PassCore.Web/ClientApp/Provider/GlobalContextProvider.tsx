import { useState, type ReactNode } from 'react';
import { GlobalContext } from './GlobalContext';
import { IGlobalContext } from '../types/Providers';

interface IGlobalContextProviderProps {
    children: ReactNode;
    settings: IGlobalContext;
}

export function GlobalContextProvider({
    children,
    settings,
}: IGlobalContextProviderProps) {
    const [getProviderValue] = useState<IGlobalContext>({ ...settings });

    return (
        <GlobalContext.Provider value={getProviderValue}>
            {children}
        </GlobalContext.Provider>
    );
}