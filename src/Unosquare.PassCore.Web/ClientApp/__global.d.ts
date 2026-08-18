export {};

declare global {
    interface Window {
        grecaptcha: {
            render: (container: HTMLElement | null, parameters: Record<string, unknown>, inherit?: boolean) => number;
            reset: (widgetId?: number) => void;
            execute: (widgetId?: number) => void;
        };
    }
}
