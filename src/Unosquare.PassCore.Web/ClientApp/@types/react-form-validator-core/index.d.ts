declare module 'react-form-validator-core' {
    import * as React from 'react';

    export interface ValidatorComponentProps {
        errorMessages?: string | string[];
        validators?: string[];
        value?: any;
        validatorListener?: (isValid: boolean) => void;
        withRequiredValidator?: boolean;
        containerProps?: Record<string, any>;
    }

    export class ValidatorComponent<P = ValidatorComponentProps, S = {}> extends React.Component<P, S> {
        validate(value?: any, includeRequired?: boolean, dryRun?: boolean): Promise<boolean>;
        getErrorMessage(): string;
        isValid(): boolean;
        makeInvalid(): void;
        makeValid(): void;
    }

    export interface ValidatorFormProps {
        onSubmit: (event?: React.FormEvent<HTMLFormElement>) => void;
        instantValidate?: boolean;
        children?: React.ReactNode;
        onError?: (errors: any[]) => void;
        debounceTime?: number;
        [key: string]: any; //
    }

    export class ValidatorForm extends React.Component<ValidatorFormProps> {
        public static addValidationRule(ruleName: string, callback: any): void;
        static getValidator(validator: string, value: any, includeRequired: boolean): Promise<boolean>;
        attachToForm(component: any): void;
        detachFromForm(component: any): void;
        instantValidate: boolean;
        debounceTime: number;
        isFormValid: (dryRun?: boolean) => Promise<boolean>;
        resetValidations: () => void;
    }
}