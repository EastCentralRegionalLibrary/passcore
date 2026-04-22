import { useMemo } from 'react';
import { Box, LinearProgress, Typography, Tooltip, useTheme } from '@mui/material';
import { zxcvbn, zxcvbnOptions } from '@zxcvbn-ts/core';
import { dictionary as commonDictionary, adjacencyGraphs } from '@zxcvbn-ts/language-common';
import { dictionary as enDictionary, translations } from '@zxcvbn-ts/language-en';

/**
 * zxcvbn-ts global configuration
 * Initialized once at module load
 */

zxcvbnOptions.setOptions({
    translations,
    graphs: adjacencyGraphs,
    dictionary: {
        ...commonDictionary,
        ...enDictionary,
    },
});

interface PasswordStrengthBarProps {
    newPassword: string;
}

type EmptyStrength = {
    kind: 'empty';
    strengthPercent: 0;
    barColor: string;
    label: string;
    guessesLog10: null;
    warning: null;
    suggestions: null;
};

type EvaluatedStrength = {
    kind: 'evaluated';
    strengthPercent: number;
    barColor: string;
    label: string;
    guessesLog10: number;
    warning: string | null;
    suggestions: string[] | null;
};

type PasswordStrength = EmptyStrength | EvaluatedStrength;

const STRENGTH_LABELS = ['Weak', 'Fair', 'Good', 'Strong', 'Very Strong'] as const;
const MIN_VISIBLE_PERCENT = 5;

export function PasswordStrengthBar({ newPassword }: PasswordStrengthBarProps) {
    const theme = useTheme();

    const strength = useMemo<PasswordStrength>(() => {
        if (!newPassword) {
            return {
                kind: 'empty' as const,
                strengthPercent: 0,
                barColor: theme.palette.grey[500],
                label: 'Enter password',
                guessesLog10: null,
                warning: null,
                suggestions: null,
            };
        }

        const result = zxcvbn(newPassword);
        const score = result.score;

        const barColor =
            score <= 1
                ? theme.palette.error.main
                : score <= 2
                  ? theme.palette.warning.main
                  : score <= 4
                    ? theme.palette.success.main
                    : theme.palette.grey[500];

        return {
            kind: 'evaluated' as const,
            strengthPercent: Math.max(MIN_VISIBLE_PERCENT, (score / 4) * 100),
            barColor: barColor,
            label: STRENGTH_LABELS[score],
            guessesLog10: result.guessesLog10,
            warning: result.feedback.warning || null,
            suggestions: result.feedback.suggestions.length ? result.feedback.suggestions : null,
        };
    }, [newPassword, theme.palette]);

    const tooltipText =
        strength.kind === 'evaluated'
            ? [
                  strength.warning,
                  strength.suggestions?.join(' '),
                  `Estimated attack cost: about 10^${strength.guessesLog10.toFixed(1)} guesses.`,
                  'This estimate assumes a fast offline attack using known patterns, ' +
                      'dictionary words, and common substitutions. Higher values mean a ' +
                      'stronger password.',
              ]
                  .filter(Boolean)
                  .join('\n\n')
            : 'Enter a password.';

    return (
        <Box sx={{ width: '100%', mt: 1.5 }}>
            <Tooltip
                title={
                    <Typography variant="caption" component="div" sx={{ whiteSpace: 'pre-line' }}>
                        {tooltipText}
                    </Typography>
                }
                arrow
                placement="top"
            >
                <LinearProgress
                    variant="determinate"
                    value={strength.strengthPercent}
                    aria-label="Password strength"
                    aria-valuemin={0}
                    aria-valuemax={100}
                    aria-valuenow={Math.round(strength.strengthPercent)}
                    aria-valuetext={strength.label}
                    sx={{
                        height: 8,
                        borderRadius: 4,
                        backgroundColor: theme.palette.mode === 'light' ? theme.palette.grey[200] : theme.palette.grey[800],
                        '& .MuiLinearProgress-bar': {
                            borderRadius: 4,
                            backgroundColor: strength.barColor,
                            transition: 'transform 0.4s cubic-bezier(0.4, 0, 0.2, 1)',
                        },
                    }}
                />
            </Tooltip>
        </Box>
    );
}
