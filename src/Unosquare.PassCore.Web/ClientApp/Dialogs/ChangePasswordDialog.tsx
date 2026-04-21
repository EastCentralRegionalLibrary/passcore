import Box from '@mui/material/Box';
import Button from '@mui/material/Button';
import Dialog from '@mui/material/Dialog';
import DialogContent from '@mui/material/DialogContent';
import DialogTitle from '@mui/material/DialogTitle';
import Typography from '@mui/material/Typography';
import { use } from 'react';
import { GlobalContext } from '../Provider/GlobalContext';

interface IChangePasswordDialogProps {
    open: boolean;
    onClose: () => void;
}

export function ChangePasswordDialog({
    open,
    onClose,
}: IChangePasswordDialogProps) {
    const { successAlertBody, successAlertTitle } = use(GlobalContext).alerts;
    return (
        <Dialog
            open={open}
            onClose={(_event, reason) => {
                if (reason !== 'backdropClick' && reason !== 'escapeKeyDown') {
                    onClose();
                }
            }}
        >
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
