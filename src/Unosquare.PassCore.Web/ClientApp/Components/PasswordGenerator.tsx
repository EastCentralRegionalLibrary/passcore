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

    const retrievePassword = () => {
        fetchRequest('api/password/generated', 'GET').then((response: any) => {
            if (response && response.password) {
                setValue(response.password);
                setLoading(false);
            }
        });
    };

    React.useEffect(() => {
        retrievePassword();
    }, []);

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
            type={visibility ? 'text' : 'Password'}
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
