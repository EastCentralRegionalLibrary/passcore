import { SnackbarMessageType } from '../types/Components';
import { SimpleObservable } from '../Utils/SimpleObservable';

export interface Snackbar {
    message: { messageText: string; messageType: SnackbarMessageType };
    milliSeconds?: number;
}

class SnackbarService extends SimpleObservable {
    private snackbar: Snackbar = {
        message: { messageText: '', messageType: 'success' },
    };

    public getSnackbar(): Snackbar {
        return this.snackbar;
    }

    public showSnackbar(message: string, type: SnackbarMessageType = 'success', milliSeconds = 5000): void {
        this.snackbar = {
            message: {
                messageText: message,
                messageType: type,
            },
            milliSeconds,
        };
        this.inform();
    }
}

export const snackbarService = new SnackbarService();
