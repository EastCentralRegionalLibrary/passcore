import Button from '@mui/material/Button/Button';
import Paper from '@mui/material/Paper/Paper';
import * as React from 'react';
import { ValidatorForm } from './functions/validations';
import { ChangePasswordDialog } from '../Dialogs/ChangePasswordDialog';
import { GlobalContext, SnackbarContext } from '../Provider/GlobalContext';
import { fetchRequest } from '../Utils/FetchRequest';
import { ChangePasswordForm } from './ChangePasswordForm';
import { IChangePasswordFormInitialModel } from '../types/Components';

export const ChangePassword: React.FunctionComponent<{}> = () => {
    const [disabled, setDisabled] = React.useState(true);
    const [submit, setSubmit] = React.useState(false);
    const [dialogIsOpen, setDialog] = React.useState(false);
    const [token, setToken] = React.useState('');
    const validatorFormRef = React.useRef<ValidatorForm | null>(null);
    const { alerts, changePasswordForm, recaptcha, validationRegex } = React.useContext(GlobalContext);
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

    const onSubmitValidatorForm = () => setSubmit(true);

    const toSubmitData = async (formData: IChangePasswordFormInitialModel): Promise<void> => {
        setDisabled(true);
        try {
            // Merge formData with the recaptcha token. Ensure `token` is available in this scope.
            const payload = JSON.stringify({ ...formData, Recaptcha: token });
            const response = await fetchRequest('api/password', 'POST', payload);

            setSubmit(false);

            if (response?.errors?.length) {
                const errorAlertMessage = response.errors
                    .map((error: any) =>
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
            // Optionally log the error here.
            sendMessage('An unexpected error occurred. Please try again later.', 'error');
        } finally {
            setDisabled(false);
        }
    };

    const onCloseDialog = () => {
        setDialog(false);
        setReset(true);
    };

    const marginButton = recaptcha.siteKey && recaptcha.siteKey !== '' ? '25px 0 0 180px' : '100px 0 0 180px';

    ValidatorForm.addValidationRule('isUserName', (value: string) =>
        new RegExp(validationRegex.usernameRegex).test(value),
    );

    ValidatorForm.addValidationRule('isUserEmail', (value: string) =>
        new RegExp(validationRegex.emailRegex).test(value),
    );

    ValidatorForm.addValidationRule('isPasswordMatch', (value: string, comparedValue: any) => value === comparedValue);

    return (
        <>
            <Paper
                style={{
                    borderRadius: '10px',
                    height: '550px',
                    marginTop: '75px',
                    width: '650px',
                    zIndex: 1,
                }}
                elevation={6}
            >
                <ValidatorForm
                    ref={validatorFormRef}
                    autoComplete="off"
                    instantValidate
                    onSubmit={onSubmitValidatorForm}
                >
                    <ChangePasswordForm
                        submitData={submit}
                        toSubmitData={toSubmitData}
                        parentRef={validatorFormRef}
                        onValidated={setDisabled}
                        shouldReset={shouldReset}
                        changeResetState={setReset}
                        setReCaptchaToken={setToken}
                        ReCaptchaToken={token}
                    />
                    <Button
                        type="submit"
                        variant="contained"
                        color="primary"
                        disabled={disabled}
                        style={{
                            margin: marginButton,
                            width: '240px',
                        }}
                    >
                        {changePasswordButtonLabel}
                    </Button>
                </ValidatorForm>
            </Paper>
            <ChangePasswordDialog open={dialogIsOpen} onClose={onCloseDialog} />
        </>
    );
};
