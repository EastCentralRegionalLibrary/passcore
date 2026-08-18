export interface IChangePasswordFormInitialModel {
    currentPassword: string;
    newPassword: string;
    newPasswordVerify: string;
    recaptcha: string;
    username: string;
}

export interface IChangePasswordFormProps {
    readonly submitData: boolean;
    readonly toSubmitData: (data: IChangePasswordFormInitialModel) => void;
    readonly onValidated: (isValid: boolean) => void;
    readonly shouldReset: boolean;
    readonly changeResetState: (state: boolean) => void;
    readonly setReCaptchaToken: (token: string) => void;
    readonly recaptchaToken: string;
}

export interface IPasswordGenProps {
    value: string;
    setValue: (password: string) => void;
}

export type SnackbarMessageType = 'success' | 'error' | 'warning' | 'info';
