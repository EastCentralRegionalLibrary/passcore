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

const STRENGTH_LABELS = ['Weak', 'Fair', 'Good', 'Strong', 'Very Strong'] as const;
const MIN_VISIBLE_PERCENT = 5;

export function PasswordStrengthBar({ newPassword }: PasswordStrengthBarProps) {
    const theme = useTheme();

    const strength = useMemo(() => {
    if (!newPassword) {
        return {
        kind: 'empty' as const,
        strengthPercent: 0,
        barColor: theme.palette.grey[500],
        label: 'Enter password',
        guessesLog10: null,
        };
    }

    const result = zxcvbn(newPassword);
    const score = result.score;

    return {
        kind: 'evaluated' as const,
        strengthPercent: Math.max(MIN_VISIBLE_PERCENT, (score / 4) * 100),
        barColor: score >= 3
        ? theme.palette.success.main
        : score >= 1
        ? theme.palette.warning.main
        : theme.palette.error.main,
        label: STRENGTH_LABELS[score],
        guessesLog10: result.guessesLog10,
    };
    }, [newPassword, theme]);


    const tooltipText = strength.kind === 'evaluated'
        ? `Estimated attack cost: about 10^${strength.guessesLog10.toFixed(1)} guesses.\n\n` +
          `This estimate assumes a fast offline attack using known patterns, ` +
          `dictionary words, and common substitutions. Higher values mean a ` +
          `stronger password.`
        : 'Enter a password to see an estimated attack difficulty.';

    return (
        <Box sx={{ width: '100%', mt: 1.5 }}>
            <Box display="flex" justifyContent="space-between" mb={0.5}>
                <Typography variant="caption" color="text.secondary" fontWeight={600}>
                    Password strength
                </Typography>

                <Tooltip
                    title={
                        <Typography variant="caption" component="div" sx={{ whiteSpace: 'pre-line' }}>
                            {tooltipText}
                        </Typography>
                    }
                    arrow
                    placement="top"
                >
                    <Typography
                        variant="caption"
                        fontWeight={600}
                        sx={{
                            color: strength.barColor,
                            cursor: 'help',
                        }}
                        tabIndex={0}
                    >
                        {strength.label}
                    </Typography>
                </Tooltip>
            </Box>

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
        </Box>
    );
}
