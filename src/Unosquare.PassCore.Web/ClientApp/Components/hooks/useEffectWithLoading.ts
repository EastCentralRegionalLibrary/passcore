import { useState, useEffect } from 'react';

export function useEffectWithLoading<T>(
    effect: () => Promise<T>,
    initialValue: T
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
        // eslint-disable-next-line react-hooks/exhaustive-deps -- Run effect once on mount like a standard loader hook
    }, []);

    return [getter, isLoading, error];
}
