import { SnackbarMessageType } from "./Components";

interface IAlerts {
    errorCaptcha: string;
    errorComplexPassword: string;
    errorConnectionLdap: string;
    errorFieldMismatch: string;
    errorFieldRequired: string;
    errorInvalidCredentials: string;
    errorInvalidDomain: string;
    errorInvalidUser: string;
    errorPasswordChangeNotAllowed: string;
    errorScorePassword: string;
    errorDistancePassword: string;
    successAlertBody: string;
    successAlertTitle: string;
    errorPwnedPassword: string;
}

interface IChangePasswordForm {
    changePasswordButtonLabel: string;
    currentPasswordHelpblock: string;
    currentPasswordLabel: string;
    helpText: string;
    newPasswordHelpblock: string;
    newPasswordLabel: string;
    newPasswordVerifyHelpblock: string;
    newPasswordVerifyLabel: string;
    usernameDefaultDomainHelperBlock: string;
    usernameHelpblock: string;
    usernameLabel: string;
}

interface IErrorsPasswordForm {
    fieldRequired: string;
    passwordMatch: string;
    usernameEmailPattern: string;
    usernamePattern: string;
}

interface IRecaptcha {
    languageCode: string;
    siteKey: string;
    privateKey: string;
}

interface IValidationRegex {
    emailRegex: string;
    usernameRegex: string;
}

export interface IGlobalContext {
    alerts: IAlerts;
    applicationTitle: string;
    changePasswordForm: IChangePasswordForm;
    changePasswordTitle: string;
    usePasswordGeneration: boolean;
    errorsPasswordForm: IErrorsPasswordForm;
    recaptcha: IRecaptcha;
    showPasswordMeter: boolean;
    useEmail: boolean;
    validationRegex: IValidationRegex;
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

/**
 * Represents the response from the password generation endpoint.
 * In this endpoint, the payload is expected to be a string (the generated password).
 */
export type PasswordGenResponse = ApiResponse<string>;

