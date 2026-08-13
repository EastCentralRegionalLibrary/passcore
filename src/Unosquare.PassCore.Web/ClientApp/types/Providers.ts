import { SnackbarMessageType } from "./Components";

/**
 * Mirrors the server-side ApiErrorCode enum.
 * Source of truth: src/Unosquare.PassCore.Common/ApiErrorCode.cs
 */
export enum ApiErrorCode {
    Generic = 0,
    FieldRequired = 1,
    FieldMismatch = 2,
    UserNotFound = 3,
    InvalidCredentials = 4,
    InvalidCaptcha = 5,
    ChangeNotPermitted = 6,
    InvalidDomain = 7,
    LdapProblem = 8,
    ComplexPassword = 9,
    MinimumScore = 10,
    MinimumDistance = 11,
    PwnedPassword = 12,
}

export interface IAlerts {
    errorCaptcha?: string | null;
    errorComplexPassword?: string | null;
    errorConnectionLdap?: string | null;
    errorFieldMismatch?: string | null;
    errorFieldRequired?: string | null;
    errorInvalidCredentials?: string | null;
    errorInvalidDomain?: string | null;
    errorInvalidUser?: string | null;
    errorPasswordChangeNotAllowed?: string | null;
    errorScorePassword?: string | null;
    errorDistancePassword?: string | null;
    successAlertBody?: string | null;
    successAlertTitle?: string | null;
    errorPwnedPassword?: string | null;
}

export interface IChangePasswordForm {
    changePasswordButtonLabel?: string | null;
    currentPasswordHelpblock?: string | null;
    currentPasswordLabel?: string | null;
    helpText?: string | null;
    newPasswordHelpblock?: string | null;
    newPasswordLabel?: string | null;
    newPasswordVerifyHelpblock?: string | null;
    newPasswordVerifyLabel?: string | null;
    usernameDefaultDomainHelperBlock?: string | null;
    usernameHelpblock?: string | null;
    usernameLabel?: string | null;
}

export interface IErrorsPasswordForm {
    fieldRequired?: string | null;
    passwordMatch?: string | null;
    usernameEmailPattern?: string | null;
    usernamePattern?: string | null;
}

export interface IRecaptcha {
    languageCode?: string | null;
    siteKey?: string | null;
}

export interface IValidationRegex {
    emailRegex?: string | null;
    usernameRegex?: string | null;
}

export interface IGlobalContext {
    alerts?: IAlerts | null;
    applicationTitle?: string | null;
    changePasswordForm?: IChangePasswordForm | null;
    changePasswordTitle?: string | null;
    usePasswordGeneration?: boolean | null;
    errorsPasswordForm?: IErrorsPasswordForm | null;
    recaptcha?: IRecaptcha | null;
    showPasswordMeter?: boolean | null;
    useEmail?: boolean | null;
    validationRegex?: IValidationRegex | null;
    minimumDistance?: number | null;
    passwordEntropy?: number | null;
    minimumScore?: number | null;
    enablePwnedPasswordCheck?: boolean | null;
}

export interface ISnackbarContext {
    sendMessage: (messageText: string, messageType?: SnackbarMessageType) => void;
}

/**
 * Represents a single error item returned from the API.
 * Corresponds to the server-side ApiErrorItem.
 */
export interface ApiError {
    /** The error code, corresponding to the ApiErrorCode enum on the server */
    errorCode: number;
    /** A descriptive error message */
    message: string;
    /** Optional field name associated with the error, if applicable */
    fieldName?: string;
}

/**
 * Represents a generic API response.
 * This mirrors the server-side ApiResult, which contains a list of errors and a payload.
 *
 * @template T - The type of the payload.
 */
export interface ApiResponse<T = unknown> {
    /** A list of error items that occurred during the API call. */
    errors?: ApiError[];
    /** The payload data returned from the API call. */
    payload?: T;
}
