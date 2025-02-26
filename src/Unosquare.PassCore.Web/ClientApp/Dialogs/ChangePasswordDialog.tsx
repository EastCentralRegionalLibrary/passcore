import Button from '@mui/material/Button/Button';
import Dialog from '@mui/material/Dialog/Dialog';
import DialogContent from '@mui/material/DialogContent/DialogContent';
import DialogTitle from '@mui/material/DialogTitle/DialogTitle';
import Typography from '@mui/material/Typography/Typography';
import * as React from 'react';
import { GlobalContext } from '../Provider/GlobalContext';

interface IChangePasswordDialogProps {
    open: boolean;
    onClose: any;
}

export const ChangePasswordDialog: React.FunctionComponent<IChangePasswordDialogProps> = ({
    open,
    onClose,
}: IChangePasswordDialogProps) => {
    const { successAlertBody, successAlertTitle } = React.useContext(GlobalContext).alerts;
    return (
        <Dialog open={open} disableEscapeKeyDown>
            <DialogTitle>{successAlertTitle}</DialogTitle>
            <DialogContent>
                <Typography variant="subtitle1">{successAlertBody}</Typography>
                <Button
                    variant="contained"
                    color="primary"
                    onClick={onClose}
                    style={{
                        margin: '10px 0 0 75%',
                        width: '25%',
                    }}
                >
                    Ok
                </Button>
            </DialogContent>
        </Dialog>
    );
};
