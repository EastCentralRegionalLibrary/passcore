import { IChangePasswordFormInitialModel } from '../types/Components';
import { IGlobalContext } from '../types/Providers';

interface ValidationErrors {
    [key: string]: string | undefined;
}

type ValidationRule = {
    name: string;
    rule: (value: string, formData: IChangePasswordFormInitialModel, context: IGlobalContext) => Promise<boolean>;
    message: string;
};

type FieldValidationRules = Partial<Record<keyof IChangePasswordFormInitialModel, ValidationRule[]>>;

const validateForm = async (
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
                        console.error(`Validator ${rule.rule.name} failed with error ${error.message}: ${error}`);
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

export type { ValidationRule, FieldValidationRules };
export default validateForm;
