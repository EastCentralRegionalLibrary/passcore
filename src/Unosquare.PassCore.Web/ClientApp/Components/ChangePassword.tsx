import Button from '@mui/material/Button';
import Paper from '@mui/material/Paper';
import { useState, use } from 'react';
import { ChangePasswordDialog } from '../Dialogs/ChangePasswordDialog';
import { GlobalContext, SnackbarContext } from '../Provider/GlobalContext';
import { fetchRequest } from '../Utils/FetchRequest';
import { ChangePasswordForm } from './ChangePasswordForm';
import { IChangePasswordFormInitialModel } from '../types/Components';
import { ApiError } from '../types/Providers';
import Box from '@mui/material/Box';

export function ChangePassword() {
    const [disabled, setDisabled] = useState(true);
    const [submit, setSubmit] = useState(false);
    const [dialogIsOpen, setDialog] = useState(false);
    const [token, setToken] = useState('');
    const globalContext = use(GlobalContext);
    const { alerts, changePasswordForm, recaptcha } = globalContext;
    const { changePasswordButtonLabel } = changePasswordForm;
    const { sendMessage } = use(SnackbarContext);
    const [shouldReset, setReset] = useState(false);
    const [isSubmitting, setIsSubmitting] = useState(false);

    const errorMessages: Record<number, string> = {
        1: alerts.errorFieldRequired,
        2: alerts.errorFieldMismatch,
        3: alerts.errorInvalidUser,
        4: alerts.errorInvalidCredentials,
        5: alerts.errorCaptcha,
        6: alerts.errorPasswordChangeNotAllowed,
        7: alerts.errorInvalidDomain,
        8: alerts.errorConnectionLdap,
        9: alerts.errorComplexPassword,
        10: alerts.errorScorePassword,
        11: alerts.errorDistancePassword,
        12: alerts.errorPwnedPassword,
    };

    const handleSubmit = () => {
        if (!isSubmitting) {
            setIsSubmitting(true);
            setSubmit(true); // triggers form submission
        }
    };

    const toSubmitData = async (formData: IChangePasswordFormInitialModel): Promise<void> => {
        setSubmit(false);
        try {
            const payload = JSON.stringify({ ...formData, Recaptcha: token });
            const response = await fetchRequest('api/password', 'POST', payload);
            if (response?.errors?.length) {
                const errorAlertMessage = response.errors
                    .map((error: ApiError) =>
                        error.errorCode === 0
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
    };

    const onCloseDialog = () => {
        setDialog(false);
        setReset(true);
    };

    return (
        <>
            <Paper elevation={6} sx={{ borderRadius: '10px', minHeight: 550, mt: '75px', zIndex: 1 }}>
                <ChangePasswordForm
                    submitData={submit}
                    toSubmitData={toSubmitData}
                    onValidated={setDisabled}
                    shouldReset={shouldReset}
                    changeResetState={setReset}
                    setReCaptchaToken={setToken}
                    ReCaptchaToken={token}
                />
                <Box
                    sx={{
                        display: 'flex',
                        justifyContent: 'center',
                        alignItems: 'center',
                        mt: recaptcha?.siteKey ? '25px' : '100px',
                    }}
                >
                    <Button
                        type="button"
                        variant="contained"
                        color="primary"
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
