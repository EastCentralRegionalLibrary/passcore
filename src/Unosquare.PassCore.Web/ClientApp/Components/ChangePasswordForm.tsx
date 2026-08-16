import Stack from '@mui/material/Stack';
import { useState, use, useEffect, FocusEvent, ChangeEvent, useMemo, useCallback } from 'react';
import TextField from '@mui/material/TextField';
import { GlobalContext } from '../Provider/GlobalContext';
import { IChangePasswordFormInitialModel, IChangePasswordFormProps } from '../types/Components';
import { PasswordGenerator } from './PasswordGenerator';
import { PasswordStrengthBar } from './PasswordStrengthBar';
import { ReCaptcha } from './ReCaptcha';
import Typography from '@mui/material/Typography';
import { parsePlainTextAndLinks } from '../Utils/HtmlStringUtils';
import { validateForm, ValidationRule, FieldValidationRules, ValidationErrors } from '../Utils/ValidateForm';
import { IGlobalContext } from '../types/Providers';

const defaultState: IChangePasswordFormInitialModel = {
    currentPassword: '',
    newPassword: '',
    newPasswordVerify: '',
    recaptcha: '',
    username: new URLSearchParams(window.location.search).get('userName') || '',
};

const isUsernamePatternValid = async (
    value: string,
    _formData: IChangePasswordFormInitialModel,
    _context: IGlobalContext,
    regex: RegExp,
): Promise<boolean> => {
    return regex.test(value);
};

const isPasswordMatchRule = async (value: string, formData: IChangePasswordFormInitialModel): Promise<boolean> => {
    return value === formData.newPassword;
};

const isRequired = (message: string): ValidationRule => ({
    name: 'isRequired',
    rule: async (value: string) => {
        return !!value.trim();
    },
    message,
});

export function ChangePasswordForm({
    submitData,
    toSubmitData,
    onValidated,
    shouldReset,
    changeResetState,
    setReCaptchaToken,
    recaptchaToken,
}: IChangePasswordFormProps) {
    const [fields, setFields] = useState<IChangePasswordFormInitialModel>(defaultState);
    const [errors, setErrors] = useState<ValidationErrors>({});
    const context = use(GlobalContext)!;
    const changePasswordForm = context?.changePasswordForm;
    const usePasswordGeneration = context?.usePasswordGeneration;
    const showPasswordMeter = context?.showPasswordMeter;
    const recaptcha = context?.recaptcha;
    const recaptchaRequired = !!recaptcha?.siteKey;
    const [touched, setTouched] = useState(() =>
        Object.keys(defaultState).reduce(
            (acc, key) => ({ ...acc, [key]: false }),
            {} as Record<keyof IChangePasswordFormInitialModel, boolean>,
        ),
    );

    const currentPasswordHelpblock = changePasswordForm?.currentPasswordHelpblock || '';
    const currentPasswordLabel = changePasswordForm?.currentPasswordLabel || '';
    const newPasswordHelpblock = changePasswordForm?.newPasswordHelpblock || '';
    const newPasswordLabel = changePasswordForm?.newPasswordLabel || '';
    const newPasswordVerifyHelpblock = changePasswordForm?.newPasswordVerifyHelpblock || '';
    const newPasswordVerifyLabel = changePasswordForm?.newPasswordVerifyLabel || '';
    const usernameDefaultDomainHelperBlock = changePasswordForm?.usernameDefaultDomainHelperBlock || '';
    const usernameHelpblock = changePasswordForm?.usernameHelpblock || '';
    const usernameLabel = changePasswordForm?.usernameLabel || '';

    const fieldHelpTextMap: Record<keyof IChangePasswordFormInitialModel, string> = useMemo(
        () => ({
            username: context?.useEmail ? usernameHelpblock : usernameDefaultDomainHelperBlock,
            currentPassword: currentPasswordHelpblock,
            recaptcha: '',
            newPassword: '',
            newPasswordVerify: newPasswordVerifyHelpblock,
        }),
        [context?.useEmail, usernameHelpblock, usernameDefaultDomainHelperBlock, currentPasswordHelpblock, newPasswordVerifyHelpblock],
    );

    const getHelperText = useCallback(
        (fieldName: keyof IChangePasswordFormInitialModel) => {
            if (errors[fieldName] && (touched[fieldName] || !!fields[fieldName])) {
                return errors[fieldName];
            }

            return fieldHelpTextMap[fieldName] || '';
        },
        [errors, touched, fields, fieldHelpTextMap],
    );

    const resetTouchedState = useCallback(() => {
        setTouched(
            Object.keys(defaultState).reduce(
                (acc, key) => ({ ...acc, [key]: false }),
                {} as Record<keyof IChangePasswordFormInitialModel, boolean>,
            ),
        );
    }, []);

    const handleBlur = useCallback((event: FocusEvent<HTMLInputElement>) => {
        const { name } = event.target;
        setTouched((prevTouched) => ({
            ...prevTouched,
            [name]: true,
        }));
    }, []);

    const handleChange = useCallback((event: ChangeEvent<HTMLInputElement>) => {
        const { name, value } = event.target;
        setFields((prevFields) => ({
            ...prevFields,
            [name]: value,
        }));
    }, []);

    const validationRegex = useMemo(
        () =>
            context?.useEmail
                ? new RegExp(context?.validationRegex?.emailRegex || '')
                : new RegExp(context?.validationRegex?.usernameRegex || ''),
        [context?.useEmail, context?.validationRegex?.emailRegex, context?.validationRegex?.usernameRegex],
    );

    const fieldRules: FieldValidationRules = useMemo(
        () => ({
            username: [
                isRequired(context?.errorsPasswordForm?.fieldRequired || 'Field is required'),
                {
                    name: 'isUsernameValid',
                    rule: (value, formData, ctx) => isUsernamePatternValid(value, formData, ctx, validationRegex),
                    message: context?.useEmail
                        ? (context?.errorsPasswordForm?.usernameEmailPattern || 'Invalid email')
                        : (context?.errorsPasswordForm?.usernamePattern || 'Invalid username'),
                },
            ],
            currentPassword: [isRequired(context?.errorsPasswordForm?.fieldRequired || 'Field is required')],
            newPassword: [isRequired(context?.errorsPasswordForm?.fieldRequired || 'Field is required')],
            newPasswordVerify: [
                isRequired(context?.errorsPasswordForm?.fieldRequired || 'Field is required'),
                {
                    name: 'isPasswordMatch',
                    rule: isPasswordMatchRule,
                    message: context?.errorsPasswordForm?.passwordMatch || 'Passwords do not match',
                },
            ],
        }),
        [context, validationRegex],
    );

    const validateAllFields = useCallback(async () => {
        const validationErrors = await validateForm(fields, context, fieldRules);
        setErrors(validationErrors);
        return validationErrors;
    }, [fields, context, fieldRules]);

    useEffect(() => {
        validateAllFields().then((validationErrors) => {
            if (!Object.keys(validationErrors).length && submitData) {
                toSubmitData(fields);
            }
        });
    }, [submitData, validateAllFields, toSubmitData, fields]);

    useEffect(() => {
        onValidated(
            Object.keys(errors).some((key) => !!errors[key]) ||
                (recaptchaRequired && recaptchaToken === ''),
        );
    }, [errors, onValidated, recaptchaRequired, recaptchaToken]);

    useEffect(() => {
        if (shouldReset) {
            setFields({ ...defaultState });
            setErrors({});
            resetTouchedState();
            changeResetState(false);
        }
    }, [shouldReset, changeResetState, resetTouchedState]);

    const setGenerated = useCallback((password: string) => {
        setFields((prevFields) => ({
            ...prevFields,
            newPassword: password,
            newPasswordVerify: password,
        }));
    }, []);

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
                error={!!errors.username && (touched.username || !!fields.username)}
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
                error={!!errors.currentPassword && (touched.currentPassword || !!fields.currentPassword)}
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
                        error={!!errors.newPassword && (touched.newPassword || !!fields.newPassword)}
                        helperText={getHelperText("newPassword")}
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
                        error={!!errors.newPasswordVerify && (touched.newPasswordVerify || !!fields.newPasswordVerify)}
                        helperText={getHelperText("newPasswordVerify")}
                    />
                </>
            )}
            {recaptchaRequired && (
                <ReCaptcha setToken={setReCaptchaToken} shouldReset={shouldReset} />
            )}
        </Stack>
    );
}
