import Container from '@mui/material/Container';
import { ChangePassword } from './ChangePassword';
import { ClientAppBar } from './ClientAppBar';
import { Footer } from './Footer';

export function EntryPoint() {
    return (
        <>
            <ClientAppBar />
            <Container maxWidth="sm" component="main">
                <ChangePassword />
                <Footer />
            </Container>
        </>
    );
}
