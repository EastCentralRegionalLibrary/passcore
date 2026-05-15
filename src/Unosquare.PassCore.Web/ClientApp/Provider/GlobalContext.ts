import { createContext } from 'react';
import { IGlobalContext, ISnackbarContext } from '../types/Providers';

export const GlobalContext = createContext<IGlobalContext | null>(null);

export const SnackbarContext = createContext<ISnackbarContext | null>(null);
