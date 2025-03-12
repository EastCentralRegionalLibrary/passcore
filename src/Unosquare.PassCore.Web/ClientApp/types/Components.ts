export interface IChangePasswordFormInitialModel {
    currentPassword: string;
    newPassword: string;
    newPasswordVerify: string;
    recaptcha: string;
    username: string;
}

export interface IChangePasswordFormProps {
    submitData: boolean;
    toSubmitData: (data: IChangePasswordFormInitialModel) => void;
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
