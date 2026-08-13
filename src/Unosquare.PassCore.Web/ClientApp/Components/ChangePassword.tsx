import Button from '@mui/material/Button';
import Paper from '@mui/material/Paper';
import { useState, use, useMemo, useCallback } from 'react';
import { ChangePasswordDialog } from '../Dialogs/ChangePasswordDialog';
import { GlobalContext, SnackbarContext } from '../Provider/GlobalContext';
import { fetchRequest } from '../Utils/FetchRequest';
import { ChangePasswordForm } from './ChangePasswordForm';
import { IChangePasswordFormInitialModel } from '../types/Components';
import { ApiError, ApiResponse, ApiErrorCode } from '../types/Providers';
import Box from '@mui/material/Box';

export function ChangePassword() {
    const context = use(GlobalContext)!;
    const alerts = context?.alerts;
    const changePasswordForm = context?.changePasswordForm;
    const changePasswordButtonLabel = changePasswordForm?.changePasswordButtonLabel || '';
    const { sendMessage } = use(SnackbarContext)!;

    const [disabled, setDisabled] = useState(true);
    const [submit, setSubmit] = useState(false);
    const [dialogIsOpen, setDialog] = useState(false);
    const [token, setToken] = useState('');
    const [shouldReset, setReset] = useState(false);
    const [isSubmitting, setIsSubmitting] = useState(false);

    const errorMessages = useMemo<Record<number, string>>(() => ({
        [ApiErrorCode.FieldRequired]: alerts?.errorFieldRequired || '',
        [ApiErrorCode.FieldMismatch]: alerts?.errorFieldMismatch || '',
        [ApiErrorCode.UserNotFound]: alerts?.errorInvalidUser || '',
        [ApiErrorCode.InvalidCredentials]: alerts?.errorInvalidCredentials || '',
        [ApiErrorCode.InvalidCaptcha]: alerts?.errorCaptcha || '',
        [ApiErrorCode.ChangeNotPermitted]: alerts?.errorPasswordChangeNotAllowed || '',
        [ApiErrorCode.InvalidDomain]: alerts?.errorInvalidDomain || '',
        [ApiErrorCode.LdapProblem]: alerts?.errorConnectionLdap || '',
        [ApiErrorCode.ComplexPassword]: alerts?.errorComplexPassword || '',
        [ApiErrorCode.MinimumScore]: alerts?.errorScorePassword || '',
        [ApiErrorCode.MinimumDistance]: alerts?.errorDistancePassword || '',
        [ApiErrorCode.PwnedPassword]: alerts?.errorPwnedPassword || '',
    }), [alerts]);

    const handleSubmit = useCallback(() => {
        if (!isSubmitting) {
            setIsSubmitting(true);
            setSubmit(true); // triggers form submission
        }
    }, [isSubmitting]);

    const toSubmitData = useCallback(async (formData: IChangePasswordFormInitialModel): Promise<void> => {
        setSubmit(false);
        try {
            const payload = JSON.stringify({ ...formData, recaptcha: token });
            const response = await fetchRequest<ApiResponse<void>>('api/password', 'POST', payload);
            if (response?.errors?.length) {
                const errorAlertMessage = response.errors
                    .map((error: ApiError) =>
                        error.errorCode === ApiErrorCode.Generic
                            ? error.message
                            : errorMessages[error.errorCode] || 'An unknown error occurred.',
                    )
                    .join(' ');
                sendMessage(errorAlertMessage, 'error');
                return;
            }
            setDialog(true);
        } catch (err) {
            const errorMsg = (err as { message?: string })?.message || String(err);
            sendMessage(`An unexpected error occurred. Please try again later. Error: ${errorMsg}`, 'error');
        } finally {
            setIsSubmitting(false);
        }
    }, [token, errorMessages, sendMessage]);

    const onCloseDialog = useCallback(() => {
        setDialog(false);
        setReset(true);
    }, []);

    return (
        <>
            <Paper
                elevation={6}
                sx={{
                    display: 'flex',
                    flexDirection: 'column',
                    borderRadius: 2,
                    minHeight: { xs: 'auto', sm: 550 },
                    zIndex: 1,
                }}
            >
                <ChangePasswordForm
                    submitData={submit}
                    toSubmitData={toSubmitData}
                    onValidated={setDisabled}
                    shouldReset={shouldReset}
                    changeResetState={setReset}
                    setReCaptchaToken={setToken}
                    recaptchaToken={token}
                />
                <Box
                    sx={{
                        display: 'flex',
                        flexGrow: 1,
                        justifyContent: 'center',
                        alignItems: 'center',
                    }}
                >
                    <Button
                        type="button"
                        variant="contained"
                        color="primary"
                        data-testid="submit-button"
                        disabled={disabled || isSubmitting}
                        sx={{ width: 240 }}
                        onClick={handleSubmit}
                    >
                        {changePasswordButtonLabel}
                    </Button>
                </Box>
            </Paper>
            <ChangePasswordDialog open={dialogIsOpen} onClose={onCloseDialog} />
        </>
    );
}
