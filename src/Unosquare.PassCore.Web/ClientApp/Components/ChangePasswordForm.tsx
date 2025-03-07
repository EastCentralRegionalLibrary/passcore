import FormGroup from '@mui/material/FormGroup/FormGroup';
import * as React from 'react';
import { TextValidator } from './TextValidator';
import { useStateForModel } from './hooks/useStateForModel';
import { GlobalContext } from '../Provider/GlobalContext';
import { IChangePasswordFormInitialModel, IChangePasswordFormProps } from '../types/Components';
import { PasswordGenerator } from './PasswordGenerator';
import { PasswordStrengthBar } from './PasswordStrengthBar';
import { ReCaptcha } from './ReCaptcha';

const defaultState: IChangePasswordFormInitialModel = {
    CurrentPassword: '',
    NewPassword: '',
    NewPasswordVerify: '',
    Recaptcha: '',
    Username: new URLSearchParams(window.location.search).get('userName') || '',
};

export const ChangePasswordForm: React.FunctionComponent<IChangePasswordFormProps> = ({
    submitData,
    toSubmitData,
    parentRef,
    onValidated,
    shouldReset,
    changeResetState,
    setReCaptchaToken,
    ReCaptchaToken,
}: IChangePasswordFormProps) => {
    const [fields, handleChange, setFields] = useStateForModel(defaultState);

    const { changePasswordForm, errorsPasswordForm, usePasswordGeneration, useEmail, showPasswordMeter, recaptcha } =
        React.useContext(GlobalContext);

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

    const { fieldRequired, passwordMatch, usernameEmailPattern, usernamePattern } = errorsPasswordForm;

    const userNameValidations = ['required', useEmail ? 'isUserEmail' : 'isUserName'];
    const userNameErrorMessages = [fieldRequired, useEmail ? usernameEmailPattern : usernamePattern];
    const userNameHelperText = useEmail ? usernameHelpblock : usernameDefaultDomainHelperBlock;

    React.useEffect(() => {
        if (submitData) {
            toSubmitData(fields);
        }
    }, [submitData]);

    React.useEffect(() => {
        if (parentRef.current !== null && parentRef.current.isFormValid !== null) {
            parentRef.current.isFormValid().then((response: any) => {
                let validated = response;
                if (recaptcha.siteKey && recaptcha.siteKey !== '') {
                    validated = validated && ReCaptchaToken !== '';
                }
                onValidated(!validated);
            });
        }
    });

    React.useEffect(() => {
        if (shouldReset) {
            setFields({ ...defaultState });
            changeResetState(false);
            if (parentRef.current && parentRef.current.resetValidations) {
                parentRef.current.resetValidations();
            }
        }
    }, [shouldReset]);

    const setGenerated = (password: string) =>
        setFields({
            NewPassword: password,
            NewPasswordVerify: password,
        });

    return (
        <FormGroup
            row={false}
            sx={{
                width: '80%',
                display: 'flex',
                flexDirection: 'column', // if row is false, use column.
                justifyContent: 'center',
                alignItems: 'stretch', // fill the width of the FormGroup
                paddingTop: '16px', // shift the first TextValidator down for aesthetics
                margin: '0 auto', // for centering the FormGroup itself
            }}
        >
            <TextValidator
                autoFocus
                inputProps={{
                    tabIndex: 1,
                }}
                sx={{
                    flex: 1,
                    margin: 'auto',
                }}
                id="Username"
                label={usernameLabel}
                variant="standard"
                helperText={userNameHelperText}
                name="Username"
                onChange={handleChange}
                validators={userNameValidations}
                value={fields.Username}
                fullWidth
                errorMessages={userNameErrorMessages}
            />
            <TextValidator
                inputProps={{
                    tabIndex: 2,
                }}
                sx={{
                    flex: 1,
                    margin: 'auto',
                }}
                label={currentPasswordLabel}
                variant="standard"
                helperText={currentPasswordHelpblock}
                id="CurrentPassword"
                name="CurrentPassword"
                onChange={handleChange}
                type="password"
                validators={['required']}
                value={fields.CurrentPassword}
                fullWidth
                errorMessages={[fieldRequired]}
            />
            {usePasswordGeneration ? (
                <PasswordGenerator value={fields.NewPassword} setValue={setGenerated} />
            ) : (
                <>
                    <TextValidator
                        inputProps={{
                            tabIndex: 3,
                        }}
                        sx={{
                            flex: 1,
                            margin: 'auto',
                        }}
                        label={newPasswordLabel}
                        variant="standard"
                        id="NewPassword"
                        name="NewPassword"
                        onChange={handleChange}
                        type="password"
                        validators={['required']}
                        value={fields.NewPassword}
                        fullWidth
                        errorMessages={[fieldRequired]}
                    />
                    {showPasswordMeter && <PasswordStrengthBar newPassword={fields.NewPassword} />}
                    <div
                        dangerouslySetInnerHTML={{ __html: newPasswordHelpblock }}
                        style={{ font: '12px Roboto,Helvetica, Arial, sans-serif', marginBottom: '15px' }}
                    />
                    <TextValidator
                        inputProps={{
                            tabIndex: 4,
                        }}
                        sx={{
                            flex: 1,
                            margin: 'auto',
                        }}
                        label={newPasswordVerifyLabel}
                        variant="standard"
                        helperText={newPasswordVerifyHelpblock}
                        id="NewPasswordVerify"
                        name="NewPasswordVerify"
                        onChange={handleChange}
                        type="password"
                        validators={['required', `isPasswordMatch:${fields.NewPassword}`]}
                        value={fields.NewPasswordVerify}
                        fullWidth
                        errorMessages={[fieldRequired, passwordMatch]}
                    />
                </>
            )}

            {recaptcha.siteKey && recaptcha.siteKey !== '' && (
                <ReCaptcha setToken={setReCaptchaToken} shouldReset={false} />
            )}
        </FormGroup>
    );
};
