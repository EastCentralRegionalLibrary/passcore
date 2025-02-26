import LinearProgress from '@mui/material/LinearProgress';
import { styled } from '@mui/material/styles';
import * as React from 'react';
import * as zxcvbn from 'zxcvbn';

const PREFIX = 'PasswordStrengthBar';

const classes = {
    progressBar: `${PREFIX}-progressBar`,
    progressBarColorHigh: `${PREFIX}-progressBarColorHigh`,
    progressBarColorLow: `${PREFIX}-progressBarColorLow`,
    progressBarColorMedium: `${PREFIX}-progressBarColorMedium`
};

// TODO jss-to-styled codemod: The Fragment root was replaced by div. Change the tag if needed.
const Root = styled('div')({
    [`& .${classes.progressBar}`]: {
        color: '#000000',
        display: 'flex',
        flexGrow: 1,
    },
    [`& .${classes.progressBarColorHigh}`]: {
        backgroundColor: '#4caf50',
    },
    [`& .${classes.progressBarColorLow}`]: {
        backgroundColor: '#ff5722',
    },
    [`& .${classes.progressBarColorMedium}`]: {
        backgroundColor: '#ffc107',
    },
});

const measureStrength = (password: string): number =>
    Math.min(
        // @ts-expect-error
        zxcvbn.default(password).guesses_log10 * 10,
        100,
    );

interface IStrengthBarProps {
    newPassword: string;
}

export const PasswordStrengthBar: React.FunctionComponent<IStrengthBarProps> = ({ newPassword }: IStrengthBarProps) => {


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
