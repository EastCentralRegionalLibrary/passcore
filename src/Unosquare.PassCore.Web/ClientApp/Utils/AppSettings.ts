//AppSettings.ts

import { IGlobalContext } from "../types/Providers";

// This should be completely implemented in IGlobalContext
/*
export interface IAppSettings {
    ValidationRegex?: {
        EmailRegex?: string;
        UsernameRegex?: string;
    };
    UsePasswordGeneration?: boolean;
    MinimumDistance?: number;
    PasswordEntropy?: number;
    ShowPasswordMeter?: boolean;
    MinimumScore?: number;
    Recaptcha?: {
        SiteKey?: string;
        PrivateKey?: string;
        LanguageCode?: string;
    };
    UseEmail?: string;
    ApplicationTitle?: string;
    ChangePasswordTitle?: string;
    ChangePasswordForm?: {
        HelpText?: string;
        UsernameLabel?: string;
        UsernameHelpblock?: string;
        UsernameDefaultDomainHelperBlock?: string;
        CurrentPasswordLabel?: string;
        CurrentPasswordHelpblock?: string;
        NewPasswordLabel?: string;
        NewPasswordHelpblock?: string;
        NewPasswordVerifyLabel?: string;
        NewPasswordVerifyHelpblock?: string;
        ChangePasswordButtonLabel?: string;
    };
    ErrorsPasswordForm?: {
        FieldRequired?: string;
        UsernamePattern?: string;
        UsernameEmailPattern?: string;
        PasswordMatch?: string;
    };
    Alerts?: {
        SuccessAlertTitle?: string;
        SuccessAlertBody?: string;
        ErrorPasswordChangeNotAllowed?: string;
        ErrorInvalidCredentials?: string;
        ErrorInvalidDomain?: string;
        ErrorInvalidUser?: string;
        ErrorCaptcha?: string;
        ErrorFieldRequired?: string;
        ErrorFieldMismatch?: string;
        ErrorComplexPassword?: string;
        ErrorConnectionLdap?: string;
        ErrorScorePassword?: string;
        ErrorDistancePassword?: string;
        ErrorPwnedPassword?: string;
    };
}
*/

export async function resolveAppSettings(): Promise<IGlobalContext> {
    const response = await fetch('api/password');

    if (!response || response.status !== 200) {
        throw new Error('Error fetching settings.');
    }

    const responseBody = await response.text();

    try {
        const data: IGlobalContext = responseBody ? JSON.parse(responseBody) : {};
        return data;
    } catch (error) {
        console.error('Error parsing AppSettings:', error);
        throw new Error('Failed to parse AppSettings.');
    }
}