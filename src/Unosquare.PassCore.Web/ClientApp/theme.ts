import { createTheme, responsiveFontSizes } from '@mui/material/styles';

const baseTheme = createTheme({
    palette: {
        error: {
            main: '#f44336',
        },
        primary: {
            main: '#304FF3',
        },
        secondary: {
            main: '#ffffff',
        },
        text: {
            primary: '#191919',
            secondary: '#000000',
        },
    },
    zIndex: {
        appBar: 1201,
    },
});

export const passcoreTheme = responsiveFontSizes(baseTheme);

// Strength bar thresholds — co-located with theme so they can be updated
// centrally if the palette ever changes.
export const strengthColors = {
    low: '#ff5722',
    medium: '#ffc107',
    high: '#4caf50',
} as const;
