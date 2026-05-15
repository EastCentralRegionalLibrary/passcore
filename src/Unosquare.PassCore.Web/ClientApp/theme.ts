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
            secondary: '#000000',
        },
    },
    zIndex: {
        appBar: 1201,
    },
});

export const passcoreTheme = responsiveFontSizes(baseTheme);
