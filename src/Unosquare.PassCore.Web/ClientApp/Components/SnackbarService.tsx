import { SimpleObservable } from 'uno-js';
import { SnackbarMessageType } from '../types/Components';

export interface Snackbar {
    message: { messageText: string; messageType: SnackbarMessageType };
    milliSeconds?: number;
    isMobile: boolean;
}

class SnackbarService extends SimpleObservable {
    private snackbar: Snackbar = {
        isMobile: false,
        message: { messageText: '', messageType: 'success' },
    };

    public getSnackbar(): Snackbar {
        return this.snackbar;
    }

    public async showSnackbar(message: string, type: SnackbarMessageType = 'success', milliSeconds = 5000): Promise<void> {
        return new Promise((resolve) => {
            this.snackbar = {
                isMobile: false,
                message: {
                    messageText: message,
                    messageType: type,
                },
                milliSeconds,
            };
            this.inform();
            resolve(); // Ensure the promise resolves
        });
    }
}

export const snackbarService = new SnackbarService();
