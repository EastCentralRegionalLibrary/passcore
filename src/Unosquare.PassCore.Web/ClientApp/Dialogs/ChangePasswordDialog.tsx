import Box from '@mui/material/Box';
import Button from '@mui/material/Button/Button';
import Dialog from '@mui/material/Dialog/Dialog';
import DialogContent from '@mui/material/DialogContent/DialogContent';
import DialogTitle from '@mui/material/DialogTitle/DialogTitle';
import Typography from '@mui/material/Typography/Typography';
import * as React from 'react';
import { GlobalContext } from '../Provider/GlobalContext';

interface IChangePasswordDialogProps {
    open: boolean;
    onClose: () => void;
}

export const ChangePasswordDialog: React.FC<IChangePasswordDialogProps> = ({
    open,
    onClose,
}: IChangePasswordDialogProps) => {
    const { successAlertBody, successAlertTitle } = React.useContext(GlobalContext).alerts;
    return (
        <Dialog open={open} disableEscapeKeyDown>
            <DialogTitle>{successAlertTitle}</DialogTitle>
            <DialogContent>
                <Typography variant="subtitle1">{successAlertBody}</Typography>
                <Box sx={{ display: 'flex', justifyContent: 'flex-end', mt: 1 }}>
                    <Button variant="contained" color="primary" onClick={onClose}>
                        Ok
                    </Button>
                </Box>
            </DialogContent>
        </Dialog>
    );
};
