import { useState, useEffect } from 'react';
import { GlobalSnackbar } from './GlobalSnackbar';
import { Snackbar, snackbarService } from './SnackbarService';

export function SnackbarContainer() {
    const [snackbar, setSnackbar] = useState<Snackbar>();

    const onUpdate = (): void => setSnackbar({ ...snackbarService.getSnackbar() });

    useEffect(() => {
        snackbarService.subscribe(onUpdate);
    }, []);

    if (!snackbar) {
        return null;
    }

    return <GlobalSnackbar milliSeconds={5000} message={snackbar.message} mobile={snackbar.isMobile} />;
};
