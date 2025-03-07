import * as React from 'react';

export function useStateForModel<T>(initialValue: T): [T, (event: React.ChangeEvent<HTMLInputElement>) => void, (values: Partial<T>) => void] {
    const [getter, setter] = React.useState(initialValue);

    const handleChange = (event: React.ChangeEvent<HTMLInputElement>): void => {
        const { name, value } = event.target;

        setter((prev) => ({
            ...prev,
            [name]: value,
        }));
    };

    const setFields = (values: Partial<T>): void => {
        setter((prev) => ({
            ...prev,
            ...values,
        }));
    };

    return [getter, handleChange, setFields];
}
