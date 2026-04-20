import Container from '@mui/material/Container';
import * as React from 'react';
import { ChangePassword } from './ChangePassword';
import { ClientAppBar } from './ClientAppBar';
import { Footer } from './Footer';

export const EntryPoint: React.FC = () => (
    <>
        <ClientAppBar />
        <Container maxWidth="sm" component="main">
            <ChangePassword />
            <Footer />
        </Container>
    </>
);
