import Box from '@mui/material/Box';
import IconButton from '@mui/material/IconButton';
import InputAdornment from '@mui/material/InputAdornment';
import TextField from '@mui/material/TextField';
import FileCopy from '@mui/icons-material/FileCopy';
import Visibility from '@mui/icons-material/Visibility';
import VisibilityOff from '@mui/icons-material/VisibilityOff';
import { use, useState, useEffect } from 'react';
import { LoadingIcon } from './LoadingIcon';
import { GlobalContext, SnackbarContext } from '../Provider/GlobalContext';
import { IPasswordGenProps } from '../types/Components';
import { fetchRequest } from '../Utils/FetchRequest';

export function PasswordGenerator({
    value,
    setValue,
}: IPasswordGenProps) {
    const { sendMessage } = use(SnackbarContext)!;
    const { changePasswordForm } = use(GlobalContext)!;
    const [visibility, setVisibility] = useState(false);
    const [isLoading, setLoading] = useState(true);

    const onMouseDownVisibility = () => setVisibility(true);
    const onMouseUpVisibility = () => setVisibility(false);

    const copyPassword = () => {
        navigator.clipboard.writeText(value);
        sendMessage('Password copied');
    };

    useEffect(() => {
        const retrievePassword = async () => {
            try {
                const response = await fetchRequest<{ password: string }>('api/password/generated', 'GET');
                if (response?.password) {
                    setValue(response.password);
                }
            } catch (error: unknown) {
                const errorMessage = error instanceof Error ? error.message : String(error);
                sendMessage(`Failed to retrieve password. Error: ${errorMessage}`, 'error');
            } finally {
                setLoading(false);
            }
        };

        retrievePassword();
    }, [sendMessage, setValue]);

    const labelText = changePasswordForm?.newPasswordLabel || 'New Password';

    return isLoading ? (
        <Box sx={{ paddingTop: '30px' }}>
            <LoadingIcon />
        </Box>
    ) : (
        <TextField
            id="generatedPassword"
            disabled
            label={labelText}
            value={value}
            type={visibility ? 'text' : 'password'}
            sx={{
                height: 20,
                my: '30px',
            }}
            slotProps={{
                input: {
                    endAdornment: (
                        <InputAdornment position="end">
                            <IconButton
                                aria-label="Toggle password visibility"
                                onMouseDown={onMouseDownVisibility}
                                onMouseUp={onMouseUpVisibility}
                                tabIndex={-1}
                                size="large"
                            >
                                {visibility ? <Visibility /> : <VisibilityOff />}
                            </IconButton>
                            <IconButton
                                aria-label="Copy password to clipboard"
                                onClick={copyPassword}
                                tabIndex={-1}
                                size="large"
                            >
                                <FileCopy />
                            </IconButton>
                        </InputAdornment>
                    ),
                },
            }}
        />
    );
}
