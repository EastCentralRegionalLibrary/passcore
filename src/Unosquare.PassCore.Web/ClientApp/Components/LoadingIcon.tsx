import CircularProgress from '@mui/material/CircularProgress';
import { styled } from '@mui/material/styles';

export const LoadingIcon = styled(CircularProgress)(({ theme }) => ({
    display: 'block',
    margin: 'auto',
    marginBottom: theme.spacing(2), // Using theme spacing for consistency
}));
