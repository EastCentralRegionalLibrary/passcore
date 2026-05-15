import { useMemo, type ReactNode } from 'react';
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
    const providerValue = useMemo(() => ({ ...settings }), [settings]);

    return (
        <GlobalContext.Provider value={providerValue}>
            {children}
        </GlobalContext.Provider>
    );
}