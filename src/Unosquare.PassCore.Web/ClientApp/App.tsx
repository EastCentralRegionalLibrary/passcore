import './vendor';

import { adaptV4Theme, createTheme, responsiveFontSizes } from '@mui/material/styles';

import ThemeProvider from '@mui/styles/ThemeProvider';
import * as React from 'react';
import { render } from 'react-dom';
import { Main } from './Main';

const theme = createTheme(adaptV4Theme({
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
}));

const passcoreTheme = responsiveFontSizes(theme);

render(
    <StyledEngineProvider injectFirst>
        <ThemeProvider theme={passcoreTheme}>
            <Main />
        </ThemeProvider>
    </StyledEngineProvider>,
    document.getElementById('rootNode'),
);
