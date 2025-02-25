import CircularProgress from '@mui/material/CircularProgress';
import styled from '@mui/styles/styled';

export const LoadingIcon = styled(CircularProgress)(() => ({
    display: 'block !important',
    margin: 'auto !important',
    marginBottom: '15px !important',
}));
