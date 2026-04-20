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

/**
 * A lightweight replacement for uno-js SimpleObservable.
 * Provides a basic observer pattern for internal service state.
 */
export class SimpleObservable {
    private observers: Array<() => void> = [];

    /**
     * Adds a callback to the observer list.
     * @param observer A function to be called when state changes.
     * @returns An unsubscribe function to remove the listener.
     */
    public subscribe(observer: () => void): () => void {
        this.observers.push(observer);
        
        // Return unsubscribe function
        return () => {
            this.observers = this.observers.filter((obs) => obs !== observer);
        };
    }

    /**
     * Notifies all subscribers that a change has occurred.
     * Marked as protected to match the uno-js implementation,
     * ensuring only the inheriting service can trigger updates.
     */
    protected inform(): void {
        this.observers.forEach((observer) => {
            try {
                observer();
            } catch (error) {
                console.error('Error in SimpleObservable subscriber:', error);
            }
        });
    }
}

export type SnackbarMessageType = 'success' | 'error' | 'warning' | 'info';
