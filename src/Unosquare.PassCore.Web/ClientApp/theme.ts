import { createTheme, responsiveFontSizes } from '@mui/material/styles';

const baseTheme = createTheme({
    palette: {
        primary: {
            main: '#304FF3',
        },
        secondary: {
            main: '#ffffff',
        },
        text: {
            primary: '#191919',
            // Override MUI's default grey secondary text with black for stronger
            // contrast on helper text; this is intentional, not a leftover.
            secondary: '#000000',
        },
    },
    zIndex: {
        appBar: 1201,
    },
});

export const passcoreTheme = responsiveFontSizes(baseTheme);
