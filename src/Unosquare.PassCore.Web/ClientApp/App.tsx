import './vendor';

import { ThemeProvider } from '@mui/material/styles';
import { createRoot } from 'react-dom/client';
import { Main } from './Main';
import { passcoreTheme } from './theme';

const rootNode = document.getElementById('rootNode');
const root = createRoot(rootNode!);
root.render(
    <ThemeProvider theme={passcoreTheme}>
        <Main />
    </ThemeProvider>,
);
