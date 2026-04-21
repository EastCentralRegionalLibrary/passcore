import Stack from '@mui/material/Stack';
import { useState, use, useEffect, FocusEvent, ChangeEvent } from 'react';
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
    currentPassword: '',
    newPassword: '',
    newPasswordVerify: '',
    recaptcha: '',
    username: new URLSearchParams(window.location.search).get('userName') || '',
};

export function ChangePasswordForm({
    submitData,
    toSubmitData,
    onValidated,
    shouldReset,
    changeResetState,
    setReCaptchaToken,
    ReCaptchaToken,
}: IChangePasswordFormProps) {
    const [fields, setFields] = useState<IChangePasswordFormInitialModel>(defaultState);
    const [errors, setErrors] = useState<{ [key: string]: string | undefined }>({});
    const context = use(GlobalContext);
    const { changePasswordForm, usePasswordGeneration, showPasswordMeter, recaptcha } = context;
    const [touched, setTouched] = useState(() =>
        Object.keys(defaultState).reduce(
            (acc, key) => ({ ...acc, [key]: false }),
            {} as Record<keyof IChangePasswordFormInitialModel, boolean>,
        ),
    );

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

    const fieldHelpTextMap: Record<keyof IChangePasswordFormInitialModel, string> = {
        username: context.useEmail ? usernameHelpblock : usernameDefaultDomainHelperBlock,
        currentPassword: currentPasswordHelpblock,
        recaptcha: '',
        newPassword: newPasswordHelpblock,
        newPasswordVerify: newPasswordVerifyHelpblock,
    };

    const getHelperText = (fieldName: keyof IChangePasswordFormInitialModel) => {
        if (errors[fieldName] && (touched[fieldName] || !!fields[fieldName])) {
            return errors[fieldName];
        }
    
        return fieldHelpTextMap[fieldName] || '';
    };

    const resetTouchedState = () => {
        setTouched(
            Object.keys(defaultState).reduce(
                (acc, key) => ({ ...acc, [key]: false }),
                {} as Record<keyof IChangePasswordFormInitialModel, boolean>,
            ),
        );
    };

    const handleBlur = (event: FocusEvent<HTMLInputElement>) => {
        const { name } = event.target;
        setTouched((prevTouched) => ({
            ...prevTouched,
            [name]: true,
        }));
    };

    const handleChange = (event: ChangeEvent<HTMLInputElement>) => {
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
        return value === formData.newPassword;
    };

    const fieldRules: FieldValidationRules = {
        username: [
            isRequired,
            {
                name: 'isUsernameValid',
                rule: isUsernamePatternValid,
                message: context.useEmail
                    ? context.errorsPasswordForm.usernameEmailPattern
                    : context.errorsPasswordForm.usernamePattern,
            } as ValidationRule,
        ],
        currentPassword: [isRequired],
        newPassword: [isRequired],
        newPasswordVerify: [
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

    useEffect(() => {
        validateAllFields().then((validationErrors) => {
            if (!Object.keys(validationErrors).length && submitData) {
                toSubmitData(fields);
            }
        });
    }, [submitData, fields, toSubmitData]);

    useEffect(() => {
        onValidated(
            Object.keys(errors).some((key) => errors[key]) ||
                (recaptcha?.siteKey && recaptcha.siteKey !== '' && ReCaptchaToken === ''),
        );
    }, [errors, onValidated, recaptcha?.siteKey, ReCaptchaToken]);

    useEffect(() => {
        if (shouldReset) {
            setFields({ ...defaultState });
            setErrors({});
            resetTouchedState();
            changeResetState(false);
        }
    }, [shouldReset, changeResetState]);

    const setGenerated = (password: string) => {
        setFields((prevFields) => ({
            ...prevFields,
            newPassword: password,
            newPasswordVerify: password,
        }));
    };

    return (
        <Stack
            spacing={2}
            sx={{ width: '80%', mx: 'auto', pt: 2 }}
        >
            <TextField
                autoFocus
                slotProps={{ htmlInput: { tabIndex: 1 } }}
                id="username"
                label={usernameLabel}
                variant="standard"
                name="username"
                onBlur={handleBlur}
                onChange={handleChange}
                value={fields.username}
                fullWidth
                error={errors.username && (touched.username || !!fields.username)}
                helperText={getHelperText("username")}
            />
            <TextField
                slotProps={{ htmlInput: { tabIndex: 2 } }}
                label={currentPasswordLabel}
                variant="standard"
                id="currentPassword"
                name="currentPassword"
                onBlur={handleBlur}
                onChange={handleChange}
                type="password"
                value={fields.currentPassword}
                fullWidth
                error={errors.currentPassword && (touched.currentPassword || !!fields.currentPassword)}
                helperText={getHelperText("currentPassword")}
            />
            {usePasswordGeneration ? (
                <PasswordGenerator value={fields.newPassword} setValue={setGenerated} />
            ) : (
                <>
                    <TextField
                        slotProps={{ htmlInput: { tabIndex: 3 } }}
                        label={newPasswordLabel}
                        variant="standard"
                        id="newPassword"
                        name="newPassword"
                        onBlur={handleBlur}
                        onChange={handleChange}
                        type="password"
                        value={fields.newPassword}
                        fullWidth
                        error={errors.newPassword && (touched.newPassword || !!fields.newPassword)}
                        // helperText={errors.NewPassword || ''}
                    />
                    {showPasswordMeter && <PasswordStrengthBar newPassword={fields.newPassword} />}
                    <Typography variant="body2" sx={{ marginBottom: '15px' }}>
                        {parsePlainTextAndLinks(newPasswordHelpblock)}
                    </Typography>
                    <TextField
                        slotProps={{ htmlInput: { tabIndex: 4 } }}
                        label={newPasswordVerifyLabel}
                        variant="standard"
                        id="newPasswordVerify"
                        name="newPasswordVerify"
                        onBlur={handleBlur}
                        onChange={handleChange}
                        type="password"
                        value={fields.newPasswordVerify}
                        fullWidth
                        error={errors.newPasswordVerify && (touched.newPasswordVerify || !!fields.newPasswordVerify)}
                        helperText={getHelperText("newPasswordVerify")}
                    />
                </>
            )}
            {recaptcha?.siteKey && recaptcha.siteKey !== '' && (
                <ReCaptcha setToken={setReCaptchaToken} shouldReset={false} />
            )}
        </Stack>
    );
};
