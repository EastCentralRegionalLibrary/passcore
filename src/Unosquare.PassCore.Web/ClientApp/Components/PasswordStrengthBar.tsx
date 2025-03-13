import LinearProgress, { LinearProgressProps } from '@mui/material/LinearProgress';
import * as React from 'react';
import * as zxcvbn from 'zxcvbn';
import { styled } from '@mui/material/styles';

interface StyledLinearProgressProps extends LinearProgressProps {
    strength: number;
}

const StyledLinearProgress = styled(LinearProgress)<StyledLinearProgressProps>(({ theme, strength }) => {
    let backgroundColor = theme.palette.error.main; // Default to error
    if (strength >= 33 && strength < 66) {
        backgroundColor = theme.palette.warning.main;
    } else if (strength >= 66) {
        backgroundColor = theme.palette.success.main;
    }

    return {
        '& .MuiLinearProgress-bar': {
            backgroundColor: backgroundColor,
        },
        display: 'flex',
        flexGrow: 1,
    };
});

const measureStrength = (password: string): number => {
    // @ts-expect-error - this is using zxcvbn, lint etc. doesn't like the import or using default
    const result = zxcvbn.default(password);
    return Math.min(result.guesses_log10 * 10, 100);
};

interface IStrengthBarProps {
    newPassword: string;
}

const PasswordStrengthBarComponent: React.FC<IStrengthBarProps> = ({ newPassword }) => {
    const newStrength = measureStrength(newPassword);

    return <StyledLinearProgress variant="determinate" value={newStrength} strength={newStrength} />;
};

export const PasswordStrengthBar = React.memo(PasswordStrengthBarComponent);
PasswordStrengthBar.displayName = 'PasswordStrengthBar';
