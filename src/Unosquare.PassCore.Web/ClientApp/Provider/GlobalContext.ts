import { createContext } from 'react';
import { IGlobalContext, ISnackbarContext } from '../types/Providers';

export const GlobalContext = createContext<IGlobalContext>({
    alerts: null,
    applicationTitle: '',
    changePasswordForm: null,
    changePasswordTitle: '',
    errorsPasswordForm: null,
    recaptcha: null,
    showPasswordMeter: false,
    useEmail: false,
    validationRegex: null,
    usePasswordGeneration: false,
});

export const SnackbarContext = createContext<ISnackbarContext>({
    sendMessage: null,
});
