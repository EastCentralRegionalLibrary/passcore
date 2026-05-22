import Box from '@mui/material/Box';
import Container from '@mui/material/Container';
import Toolbar from '@mui/material/Toolbar';
import { ChangePassword } from './ChangePassword';
import { ClientAppBar } from './ClientAppBar';
import { Footer } from './Footer';

export function EntryPoint() {
    return (
        <Box
            sx={{
                display: 'flex',
                flexDirection: 'column',
                minHeight: '100vh',
            }}
        >
            <ClientAppBar />
            <Toolbar /> {/* Spacer for fixed AppBar */}
            <Box
                component="main"
                sx={{
                    flexGrow: 1,
                    display: 'flex',
                    flexDirection: 'column',
                    py: { xs: 4, sm: 6 },
                }}
            >
                <Container maxWidth="sm">
                    <ChangePassword />
                    <Footer />
                </Container>
            </Box>
        </Box>
    );
}
