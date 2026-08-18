import { IChangePasswordFormInitialModel } from '../types/Components';
import { IGlobalContext } from '../types/Providers';

export interface ValidationErrors {
    [key: string]: string | undefined;
}

export type ValidationRule = {
    name: string;
    rule: (value: string, formData: IChangePasswordFormInitialModel, context: IGlobalContext) => Promise<boolean>;
    message: string;
};

type FieldValidationRules = Partial<Record<keyof IChangePasswordFormInitialModel, ValidationRule[]>>;

export const validateForm = async (
    formData: IChangePasswordFormInitialModel,
    context: IGlobalContext,
    fieldRules: FieldValidationRules,
): Promise<ValidationErrors> => {
    const errors: ValidationErrors = {};

    await Promise.all(
        Object.entries(fieldRules).map(async ([fieldName, rules]) => {
            if (!rules) return;

            const value = formData[fieldName as keyof IChangePasswordFormInitialModel];

            let fieldError: string | undefined;
            for (const rule of rules) {
                try {
                    const valid = await rule.rule(value, formData, context);
                    if (!valid) {
                        fieldError = rule.message;
                        break;
                    }
                } catch (error) {
                    const errorMessage = error instanceof Error ? error.message : String(error);
                    console.error(`Validator ${rule.rule.name} failed with error ${errorMessage}: ${error}`);
                    fieldError = rule.message;
                    break;
                }
            }
            if (fieldError) {
                errors[fieldName] = fieldError;
            }
        }),
    );

    return errors;
};

export type { FieldValidationRules };
