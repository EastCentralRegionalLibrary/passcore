import * as React from 'react';
import { GlobalSnackbar } from './GlobalSnackbar';
import { Snackbar } from './SnackbarService';

interface SnackbarContainerProps {
    snackbar: Snackbar;
}

export const SnackbarContainer: React.FC<SnackbarContainerProps> = ({ snackbar }) => {
    if (!snackbar || !snackbar.message.messageText) {
        return null;
    }

    return (
        <GlobalSnackbar
            milliSeconds={snackbar.milliSeconds ?? 5000}
            message={snackbar.message}
            mobile={snackbar.isMobile}
        />
    );
};
