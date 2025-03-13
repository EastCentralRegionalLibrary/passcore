import './vendor';

import { StyledEngineProvider, createTheme, responsiveFontSizes, ThemeProvider } from '@mui/material/styles';

import * as React from 'react';
import * as ReactDOMClient from 'react-dom/client';
import { Main } from './Main';

import { common, red, amber, blue, green, grey, } from '@mui/material/colors';

const theme = createTheme({
    palette: {
        error: {
            main: red[600],  // Define the error color
        },
        warning: {
            main: amber[700],  // Use amber for warnings
        },
        info: {
            main: blue[600],  // Use blue for info
        },
        success: {
            main: green[700],  // Use green for success
        },
        primary: {
            main: blue[700],  // Define blue as the primary color
        },
        secondary: {
            main: common.white,  // Use white for secondary color
        },
        text: {
            primary: grey[900],  // Use dark grey for primary text color
            secondary: common.black, // use black for secondary text color
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
