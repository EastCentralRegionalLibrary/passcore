import { useState, useEffect, useCallback } from 'react';
import { GlobalSnackbar } from './GlobalSnackbar';
import { Snackbar, snackbarService } from './SnackbarService';

export function SnackbarContainer() {
    const [snackbar, setSnackbar] = useState<Snackbar>();

    const onUpdate = useCallback((): void => setSnackbar({ ...snackbarService.getSnackbar() }), []);

    useEffect(() => {
        return snackbarService.subscribe(onUpdate);
    }, [onUpdate]);

    if (!snackbar) {
        return null;
    }

    return <GlobalSnackbar milliSeconds={5000} message={snackbar.message} />;
}
