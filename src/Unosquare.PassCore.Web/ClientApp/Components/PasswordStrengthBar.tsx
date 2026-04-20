import LinearProgress from '@mui/material/LinearProgress';
import * as React from 'react';
import * as zxcvbn from 'zxcvbn';
import { strengthColors } from '../theme';

const measureStrength = (password: string): number =>
    Math.min(
        // @ts-expect-error - zxcvbn module type
        zxcvbn.default(password).guesses_log10 * 10,
        100,
    );

const getBarColor = (strength: number): string => {
    if (strength < 33) return strengthColors.low;
    if (strength < 66) return strengthColors.medium;
    return strengthColors.high;
};

interface IStrengthBarProps {
    newPassword: string;
}

export const PasswordStrengthBar: React.FC<IStrengthBarProps> = ({ newPassword }) => {
    const strength = measureStrength(newPassword);
    const barColor = getBarColor(strength);

    return (
        <LinearProgress
            variant="determinate"
            value={strength}
            sx={{
                flexGrow: 1,
                '& .MuiLinearProgress-bar': {
                    backgroundColor: barColor,
                },
            }}
        />
    );
};
