import Button from '@mui/material/Button';
import Paper from '@mui/material/Paper';
import * as React from 'react';
import { ChangePasswordDialog } from '../Dialogs/ChangePasswordDialog';
import { GlobalContext, SnackbarContext } from '../Provider/GlobalContext';
import { fetchRequest } from '../Utils/FetchRequest';
import { ChangePasswordForm } from './ChangePasswordForm';
import { IChangePasswordFormInitialModel } from '../types/Components';
import { ApiError } from '../types/Providers';

export const ChangePassword: React.FC = () => {
    const [disabled, setDisabled] = React.useState(true);
    const [submit, setSubmit] = React.useState(false);
    const [dialogIsOpen, setDialog] = React.useState(false);
    const [token, setToken] = React.useState('');
    const globalContext = React.useContext(GlobalContext);
    const { alerts, changePasswordForm, recaptcha } = globalContext;
    const { changePasswordButtonLabel } = changePasswordForm;
    const { sendMessage } = React.useContext(SnackbarContext);
    const [shouldReset, setReset] = React.useState(false);

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

    const paperStyle = {
        borderRadius: '10px',
        height: '550px',
        marginTop: '75px',
        width: '650px',
        zIndex: 1,
    };

    const buttonStyle = {
        margin: recaptcha?.siteKey ? '25px 0 0 180px' : '100px 0 0 180px',
        width: '240px',
    };

    const toSubmitData = async (formData: IChangePasswordFormInitialModel): Promise<void> => {
        setDisabled(true);
        try {
            const payload = JSON.stringify({ ...formData, Recaptcha: token });
            const response = await fetchRequest('api/password', 'POST', payload);

            if (response?.errors?.length) {
                const errorAlertMessage = response.errors
                    .map((error: ApiError) => error.errorCode === 0 ? error.message : errorMessages[error.errorCode] || 'An unknown error occurred.')
                    .join(' ');
                sendMessage(errorAlertMessage, 'error');
                return;
            }
            setDialog(true);
        } catch (err) {
            const errorMsg = (err as { message?: string })?.message || String(err);
            sendMessage(`An unexpected error occurred. Please try again later. Error: ${errorMsg}`, 'error');
        } finally {
            setDisabled(false);
        }
    };

    const onCloseDialog = () => {
        setDialog(false);
        setReset(true);
    };

    return (
        <>
            <Paper sx={paperStyle} elevation={6}>
                <ChangePasswordForm
                    submitData={submit}
                    toSubmitData={toSubmitData}
                    onValidated={setDisabled}
                    shouldReset={shouldReset}
                    changeResetState={setReset}
                    setReCaptchaToken={setToken}
                    ReCaptchaToken={token}
                />
                <Button
                    type="button"
                    variant="contained"
                    color="primary"
                    disabled={disabled}
                    sx={buttonStyle}
                    onClick={() => setSubmit(true)}
                >
                    {changePasswordButtonLabel}
                </Button>
            </Paper>
            <ChangePasswordDialog open={dialogIsOpen} onClose={onCloseDialog} />
        </>
    );
};