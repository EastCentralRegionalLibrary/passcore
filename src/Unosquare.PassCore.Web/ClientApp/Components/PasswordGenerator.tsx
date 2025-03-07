import IconButton from '@mui/material/IconButton/IconButton';
import InputAdornment from '@mui/material/InputAdornment/InputAdornment';
import TextField from '@mui/material/TextField/TextField';
import FileCopy from '@mui/icons-material/FileCopy';
import Visibility from '@mui/icons-material/Visibility';
import VisibilityOff from '@mui/icons-material/VisibilityOff';
import * as React from 'react';
import { LoadingIcon } from './LoadingIcon';
import { SnackbarContext } from '../Provider/GlobalContext';
import { IPasswordGenProps } from '../types/Components';
import { fetchRequest } from '../Utils/FetchRequest';
import { PasswordGenResponse } from '../types/Providers'; // Imported shared API type

export const PasswordGenerator: React.FunctionComponent<IPasswordGenProps> = ({
    value,
    setValue,
}: IPasswordGenProps) => {
    const { sendMessage } = React.useContext(SnackbarContext);
    const [visibility, setVisibility] = React.useState(false);
    const [isLoading, setLoading] = React.useState(true);

    const onMouseDownVisibility = () => setVisibility(true);
    const onMouseUpVisibility = () => setVisibility(false);

    const copyPassword = () => {
        navigator.clipboard.writeText(value);
        sendMessage('Password copied');
    };

    React.useEffect(() => {
        const retrievePassword = async () => {
            try {
                // Cast response as PasswordGenResponse which expects a payload of type string.
                const response = (await fetchRequest('api/password/generated', 'GET')) as PasswordGenResponse;
                if (response?.payload) {
                    setValue(response.payload);
                } else if (response?.errors?.length) {
                    const errorMsg = response.errors.map((error) => error.message).join(' ');
                    sendMessage(errorMsg, 'error');
                }
            } catch (error: unknown) {
                // Use type narrowing to extract the error message
                const errorMessage = error instanceof Error ? error.message : String(error);
                sendMessage(`Failed to retrieve password. Error: ${errorMessage}`, 'error');
            } finally {
                setLoading(false);
            }
        };

        retrievePassword();
    }, [sendMessage, setValue]);

    return isLoading ? (
        <div style={{ paddingTop: '30px' }}>
            <LoadingIcon />
        </div>
    ) : (
        <TextField
            id="generatedPassword"
            disabled
            label="New Password"
            value={value}
            type={visibility ? 'text' : 'password'}
            style={{
                height: '20px',
                margin: '30px 0 30px 0',
            }}
            InputProps={{
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
            }}
        />
    );
};
