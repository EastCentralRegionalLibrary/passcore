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
    fieldRules: FieldValidationRules
): Promise<ValidationErrors> => {
    const errors: ValidationErrors = {};

    await Promise.all(
        Object.entries(fieldRules).map(async ([fieldName, rules]) => {
            if (!rules) return;

            const value = formData[fieldName as keyof IChangePasswordFormInitialModel];

            const results = await Promise.all(
                rules.map(async (rule) => {
                    try {
                        // Attempt to run the validation rule
                        const valid = await rule.rule(value, formData, context);
                        return { valid, message: rule.message };
                    } catch (error) {
                        // If an error occurs, treat it as failed validation
                        const errorMessage = error instanceof Error ? error.message : String(error);
                        console.error(`Validator ${rule.rule.name} failed with error ${errorMessage}: ${error}`);
                        return { valid: false, message: rule.message };
                    }
                })
            );

            const errorRule = results.find((r) => !r.valid);
            if (errorRule) {
                errors[fieldName] = errorRule.message;
            }
        })
    );

    return errors;
};

export type { FieldValidationRules };
