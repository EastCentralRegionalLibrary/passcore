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
    const hasPassword = newPassword.length > 0;

    const result = useMemo(() => (hasPassword ? zxcvbn(newPassword) : null), [hasPassword, newPassword]);

    const score = hasPassword ? result.score : 0;
    const strengthPercent = hasPassword ? Math.max(MIN_VISIBLE_PERCENT, (score / 4) * 100) : 0;

    const computedColor = useMemo(() => {
        switch (score) {
            case 0:
                return theme.palette.error.main;
            case 1:
            case 2:
                return theme.palette.warning.main;
            case 3:
            case 4:
                return theme.palette.success.main;
            default:
                return theme.palette.grey[500];
        }
    }, [score, theme.palette]);

    const barColor = hasPassword ? computedColor : theme.palette.grey[500];

    const label = hasPassword ? STRENGTH_LABELS[score] : 'Enter password';

    const guessesLog10 = hasPassword ? result.guessesLog10 : 0;

    const tooltipText = hasPassword
        ? `Estimated attack cost: about 10^${guessesLog10.toFixed(1)} guesses.\n\n` +
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
                            color: barColor,
                            cursor: 'help',
                        }}
                        tabIndex={0}
                    >
                        {label}
                    </Typography>
                </Tooltip>
            </Box>

            <LinearProgress
                variant="determinate"
                value={strengthPercent}
                aria-label="Password strength"
                aria-valuemin={0}
                aria-valuemax={100}
                aria-valuenow={Math.round(strengthPercent)}
                aria-valuetext={label}
                sx={{
                    height: 8,
                    borderRadius: 4,
                    backgroundColor: theme.palette.mode === 'light' ? theme.palette.grey[200] : theme.palette.grey[800],
                    '& .MuiLinearProgress-bar': {
                        borderRadius: 4,
                        backgroundColor: barColor,
                        transition: 'transform 0.4s cubic-bezier(0.4, 0, 0.2, 1)',
                    },
                }}
            />
        </Box>
    );
}
