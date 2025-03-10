import FormGroup from '@mui/material/FormGroup';
import * as React from 'react';
import TextField from '@mui/material/TextField';
import { GlobalContext } from '../Provider/GlobalContext';
import { IChangePasswordFormInitialModel, IChangePasswordFormProps } from '../types/Components';
import { PasswordGenerator } from './PasswordGenerator';
import { PasswordStrengthBar } from './PasswordStrengthBar';
import { ReCaptcha } from './ReCaptcha';
import Typography from '@mui/material/Typography';
import { parsePlainTextAndLinks } from '../Utils/HtmlStringUtils';
import validateForm, { ValidationRule, FieldValidationRules } from '../Utils/ValidateForm';
import { IGlobalContext } from '../types/Providers';

const defaultState: IChangePasswordFormInitialModel = {
    CurrentPassword: '',
    NewPassword: '',
    NewPasswordVerify: '',
    Recaptcha: '',
    Username: new URLSearchParams(window.location.search).get('userName') || '',
};

export const ChangePasswordForm: React.FC<IChangePasswordFormProps> = ({
    submitData,
    toSubmitData,
    onValidated,
    shouldReset,
    changeResetState,
    setReCaptchaToken,
    ReCaptchaToken,
}) => {
    const [fields, setFields] = React.useState<IChangePasswordFormInitialModel>(defaultState);
    const [errors, setErrors] = React.useState<{ [key: string]: string | undefined }>({});
    const context = React.useContext(GlobalContext);
    const { changePasswordForm, usePasswordGeneration, showPasswordMeter, recaptcha } = context;

    const {
        currentPasswordHelpblock,
        currentPasswordLabel,
        newPasswordHelpblock,
        newPasswordLabel,
        newPasswordVerifyHelpblock,
        newPasswordVerifyLabel,
        usernameDefaultDomainHelperBlock,
        usernameHelpblock,
        usernameLabel,
    } = changePasswordForm;

    const userNameHelperText = context.useEmail ? usernameHelpblock : usernameDefaultDomainHelperBlock;

    const handleChange = (event: React.ChangeEvent<HTMLInputElement>) => {
        const { name, value } = event.target;
        setFields((prevFields) => ({
            ...prevFields,
            [name]: value,
        }));
    };

    const isRequired: ValidationRule = {
        name: 'isRequired',
        rule: async (value: string) => {
            return !!value.trim(); // Returns a Promise resolving to a boolean
        },
        message: context.errorsPasswordForm.fieldRequired,
    };

    const isUsernamePatternValid = async (
        value: string,
        _formData: IChangePasswordFormInitialModel,
        context: IGlobalContext,
    ): Promise<boolean> => {
        const regex = context.useEmail
            ? new RegExp(context.validationRegex.emailRegex)
            : new RegExp(context.validationRegex.usernameRegex);
        return regex.test(value);
    };

    const isPasswordMatchRule = async (value: string, formData: IChangePasswordFormInitialModel): Promise<boolean> => {
        return value === formData.NewPassword;
    };

    const fieldRules: FieldValidationRules = {
        Username: [
            isRequired,
            {
                name: 'isUsernameValid',
                rule: isUsernamePatternValid,
                message: context.useEmail
                    ? context.errorsPasswordForm.usernameEmailPattern
                    : context.errorsPasswordForm.usernamePattern,
            } as ValidationRule,
        ],
        CurrentPassword: [isRequired],
        NewPassword: [isRequired],
        NewPasswordVerify: [
            isRequired,
            {
                name: 'isPasswordMatch',
                rule: isPasswordMatchRule,
                message: context.errorsPasswordForm.passwordMatch,
            } as ValidationRule,
        ],
    };

    const validateAllFields = async () => {
        const validationErrors = await validateForm(fields, context, fieldRules);
        setErrors(validationErrors);
        return validationErrors;
    };

    React.useEffect(() => {
        if (submitData) {
            validateAllFields().then((validationErrors) => {
                if (Object.keys(validationErrors).length === 0) {
                    toSubmitData(fields);
                }
            });
        }
    }, [submitData, fields, toSubmitData]);

    React.useEffect(() => {
        onValidated(
            Object.keys(errors).some((key) => errors[key]) ||
                (recaptcha?.siteKey && recaptcha.siteKey !== '' && ReCaptchaToken === ''),
        );
    }, [errors, onValidated, recaptcha?.siteKey, ReCaptchaToken]);

    React.useEffect(() => {
        if (shouldReset) {
            setFields({ ...defaultState });
            setErrors({});
            changeResetState(false);
        }
    }, [shouldReset, changeResetState]);

    const setGenerated = (password: string) => {
        setFields((prevFields) => ({
            ...prevFields,
            NewPassword: password,
            NewPasswordVerify: password,
        }));
    };

    const formGroupStyle = {
        width: '80%',
        display: 'flex',
        flexDirection: 'column',
        justifyContent: 'center',
        alignItems: 'stretch',
        paddingTop: '16px',
        margin: '0 auto',
    };

    return (
        <FormGroup row={false} sx={formGroupStyle}>
            <TextField
                autoFocus
                slotProps={{ htmlInput: { tabIndex: 1 } }}
                sx={{ flex: 1, margin: 'auto' }}
                id="Username"
                label={usernameLabel}
                variant="standard"
                name="Username"
                onChange={handleChange}
                value={fields.Username}
                fullWidth
                error={!!errors.Username}
                helperText={errors.Username || userNameHelperText}
            />
            <TextField
                slotProps={{ htmlInput: { tabIndex: 2 } }}
                sx={{ flex: 1, margin: 'auto' }}
                label={currentPasswordLabel}
                variant="standard"
                id="CurrentPassword"
                name="CurrentPassword"
                onChange={handleChange}
                type="password"
                value={fields.CurrentPassword}
                fullWidth
                error={!!errors.CurrentPassword}
                helperText={errors.CurrentPassword || currentPasswordHelpblock}
            />
            {usePasswordGeneration ? (
                <PasswordGenerator value={fields.NewPassword} setValue={setGenerated} />
            ) : (
                <>
                    <TextField
                        slotProps={{ htmlInput: { tabIndex: 3 } }}
                        sx={{ flex: 1, margin: 'auto' }}
                        label={newPasswordLabel}
                        variant="standard"
                        id="NewPassword"
                        name="NewPassword"
                        onChange={handleChange}
                        type="password"
                        value={fields.NewPassword}
                        fullWidth
                        error={!!errors.NewPassword}
                        helperText={errors.NewPassword || ''}
                    />
                    {showPasswordMeter && <PasswordStrengthBar newPassword={fields.NewPassword} />}
                    <Typography variant="body2" sx={{ marginBottom: '15px' }}>
                        {parsePlainTextAndLinks(newPasswordHelpblock)}
                    </Typography>
                    <TextField
                        slotProps={{ htmlInput: { tabIndex: 4 } }}
                        sx={{ flex: 1, margin: 'auto' }}
                        label={newPasswordVerifyLabel}
                        variant="standard"
                        id="NewPasswordVerify"
                        name="NewPasswordVerify"
                        onChange={handleChange}
                        type="password"
                        value={fields.NewPasswordVerify}
                        fullWidth
                        error={!!errors.NewPasswordVerify}
                        helperText={errors.NewPasswordVerify || newPasswordVerifyHelpblock}
                    />
                </>
            )}
            {recaptcha?.siteKey && recaptcha.siteKey !== '' && (
                <ReCaptcha setToken={setReCaptchaToken} shouldReset={false} />
            )}
        </FormGroup>
    );
};
