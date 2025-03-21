import LinearProgress from '@mui/material/LinearProgress';
import makeStyles from '@mui/styles/makeStyles';
import * as React from 'react';
import * as zxcvbn from 'zxcvbn';

const useStyles = makeStyles({
    progressBar: {
        color: '#000000',
        display: 'flex',
        flexGrow: 1,
    },
    progressBarColorHigh: {
        backgroundColor: '#4caf50',
    },
    progressBarColorLow: {
        backgroundColor: '#ff5722',
    },
    progressBarColorMedium: {
        backgroundColor: '#ffc107',
    },
});

const measureStrength = (password: string): number =>
    Math.min(
        // @ts-expect-error - this is using zxcvbn, lint etc. doesn't like the import or using default
        zxcvbn.default(password).guesses_log10 * 10,
        100,
    );

interface IStrengthBarProps {
    newPassword: string;
}

export const PasswordStrengthBar: React.FC<IStrengthBarProps> = ({ newPassword }: IStrengthBarProps) => {
    const classes = useStyles({});

    const getProgressColor = (strength: number) => ({
        barColorPrimary:
            strength < 33
                ? classes.progressBarColorLow
                : strength < 66
                  ? classes.progressBarColorMedium
                  : classes.progressBarColorHigh,
    });

    const newStrength = measureStrength(newPassword);
    const primeColor = getProgressColor(newStrength);

    return (
        <LinearProgress
            classes={primeColor}
            variant="determinate"
            value={newStrength}
            className={classes.progressBar}
        />
    );
};
