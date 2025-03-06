import TextField, { TextFieldProps } from '@mui/material/TextField';
import * as React from 'react';
import { ValidatorComponent, ValidatorComponentProps } from 'react-form-validator-core';
import { humanize } from 'uno-js';

export type TextValidatorProps = ValidatorComponentProps & TextFieldProps;

export class TextValidator extends ValidatorComponent<TextValidatorProps> {
    /**
     * Renders the TextField component with validation logic.
     */
    public renderValidatorComponent() {
        const { error, helperText, label, id, ...rest } = this.props;

        return (
            <TextField
                {...rest}
                label={label || humanize(id)}
                error={!this.isValid() || error}
                helperText={(!this.isValid() && this.getErrorMessage()) || helperText}
            />
        );
    }
}
