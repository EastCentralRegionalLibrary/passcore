import { MutableRefObject } from 'react';

export interface IChangePasswordFormInitialModel {
    CurrentPassword: string;
    NewPassword: string;
    NewPasswordVerify: string;
    Recaptcha: string;
    Username: string;
}

export interface IChangePasswordFormProps {
    submitData: boolean;
    toSubmitData: (data: IChangePasswordFormInitialModel) => void;
    parentRef: MutableRefObject<{ isFormValid: () => Promise<boolean>; resetValidations?: () => void } | null>;
    onValidated: (isValid: boolean) => void;
    shouldReset: boolean;
    changeResetState: (state: boolean) => void;
    setReCaptchaToken: (token: string) => void;
    ReCaptchaToken: string;
}

export interface IPasswordGenProps {
    value: string;
    setValue: (password: string) => void;
}

export type SnackbarMessageType = 'success' | 'error' | 'warning' | 'info';
