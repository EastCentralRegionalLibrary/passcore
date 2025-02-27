import './vendor';

import { StyledEngineProvider, createTheme, responsiveFontSizes, ThemeProvider } from '@mui/material/styles';

import * as React from 'react';
import * as ReactDOMClient from 'react-dom/client';
import { Main } from './Main';

const theme = createTheme({
    palette: {
        error: {
            main: '#f44336',
        },
        primary: {
            main: '#304FF3',
        },
        secondary: {
            main: '#fff',
        },
        text: {
            primary: '#191919',
            secondary: '#000',
        },
    },
    zIndex: {
        appBar: 1201,
    },
});

const passcoreTheme = responsiveFontSizes(theme);
const rootNode = document.getElementById('rootNode');
const root = ReactDOMClient.createRoot(rootNode);
root.render(
    <StyledEngineProvider injectFirst>
        <ThemeProvider theme={passcoreTheme}>
            <Main />
        </ThemeProvider>
    </StyledEngineProvider>,
);
