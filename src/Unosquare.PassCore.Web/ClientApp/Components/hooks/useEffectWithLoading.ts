import { useState, useEffect, type DependencyList } from 'react';

export function useEffectWithLoading<T>(
    effect: () => Promise<T>,
    initialValue: T,
    inputs: DependencyList
): [T, boolean, Error | null] {
    const [getter, setter] = useState(initialValue);
    const [isLoading, setIsLoading] = useState(true);
    const [error, setError] = useState<Error | null>(null);

    useEffect(() => {
        let _isMounted = true;
        setError(null);
        setIsLoading(true);

        effect()
            .then((resp: T) => {
                if (_isMounted) {
                    setter(resp);
                    setIsLoading(false);
                }
            })
            .catch((err) => {
                if (_isMounted) {
                    setError(err instanceof Error ? err : new Error(String(err)));
                    setIsLoading(false);
                }
            });

        return (): void => {
            _isMounted = false;
        };
    }, inputs);

    return [getter, isLoading, error];
}
