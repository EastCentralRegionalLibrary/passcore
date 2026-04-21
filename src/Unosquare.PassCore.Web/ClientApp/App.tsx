import './vendor';

import { ThemeProvider } from '@mui/material/styles';
import * as ReactDOMClient from 'react-dom/client';
import { Main } from './Main';
import { passcoreTheme } from './theme';

const rootNode = document.getElementById('rootNode');
const root = ReactDOMClient.createRoot(rootNode!);
root.render(
    <ThemeProvider theme={passcoreTheme}>
        <Main />
    </ThemeProvider>,
);
