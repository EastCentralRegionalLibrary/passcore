import { Component, createRef } from 'react';

const noop = (): void => undefined;
interface IReCaptchaProps {
    badge: 'bottomright' | 'bottomleft' | 'inline';
    hl: string;
    inherit: boolean;
    isolated: boolean;
    onError: () => void;
    onExpired: () => void;
    onLoad: () => void;
    onSuccess: (recaptchaToken: string) => void;
    render: string;
    sitekey: string;
    size: 'compact' | 'normal' | 'invisible';
    tabIndex: string | number;
    theme: 'dark' | 'light';
    type: string;
}

interface IReCaptchaState {
    ready: boolean;
}

/**
 * Wraps the Google reCAPTCHA v2 widget.
 * Implemented as a class component to expose imperative `reset()` and `execute()`
 * methods via ref, which are required by ReCaptcha.tsx to control the widget lifecycle.
 * Converting to a functional component would require useImperativeHandle.
 */
class GoogleReCaptcha extends Component<Partial<IReCaptchaProps>, IReCaptchaState> {
    protected static defaultProps: Partial<IReCaptchaProps> = {
        badge: 'bottomright',
        hl: 'en',
        inherit: true,
        isolated: false,
        onError: noop,
        onExpired: noop,
        onLoad: noop,
        onSuccess: noop,
        size: 'normal',
        tabIndex: 0,
        theme: 'light',
        type: 'image',
    };

    private readyIntervalId!: ReturnType<typeof setInterval>;
    private recaptcha = createRef<HTMLDivElement>();

    private widgetId: number | undefined;

    constructor(props: Partial<IReCaptchaProps>) {
        super(props);
        this.state = {
            ready: this.isReady(),
        };
    }

    public isReady = () =>
        typeof window !== 'undefined' &&
        typeof window.grecaptcha !== 'undefined' &&
        typeof window.grecaptcha.render === 'function';

    public componentWillUnmount() {
        clearInterval(this.readyIntervalId);
    }

    public componentDidMount() {
        this.readyIntervalId = setInterval(() => this._updateReadyState(), 1000);
        this.renderManually();
    }

    public componentDidUpdate(_prevProps: IReCaptchaProps, prevState: IReCaptchaState) {
        if (!prevState.ready && this.state.ready) {
            this.renderManually();
        }
    }

    public reset = () => {
        if (this.isReady() && this.widgetId !== undefined) {
            this.grecaptcha().reset(this.widgetId);
        }
    };

    public execute = () => {
        if (this.isReady() && this.widgetId !== undefined) {
            this.grecaptcha().execute(this.widgetId);
        }
    };

    public shouldComponentUpdate(_nextProps: Partial<IReCaptchaProps>, nextState: IReCaptchaState) {
        return !this.state.ready && nextState.ready;
    }

    public render() {
        const {
            badge,
            hl,
            inherit,
            isolated,
            onError,
            onExpired,
            onLoad,
            onSuccess,
            render,
            sitekey,
            size,
            tabIndex,
            theme,
            type,
            ...rest
        } = this.props;

        return (
            <div
                ref={this.recaptcha}
                data-sitekey={sitekey}
                data-theme={theme}
                data-type={type}
                data-size={size}
                data-badge={badge}
                data-tabindex={tabIndex}
                {...rest}
            />
        );
    }

    private readonly grecaptcha = () => window.grecaptcha;

    private readonly renderManually = () => {
        if (this.grecaptcha() && this.grecaptcha().render && this.widgetId === undefined) {
            this.widgetId = this.grecaptcha().render(
                this.recaptcha.current,
                {
                    badge: this.props.badge,
                    callback: this.props.onSuccess,
                    'error-callback': this.props.onError,
                    'expired-callback': this.props.onExpired,
                    isolated: this.props.isolated,
                    sitekey: this.props.sitekey,
                    size: this.props.size,
                    tabindex: this.props.tabIndex,
                    theme: this.props.theme,
                },
                this.props.inherit,
            );
        }
    };

    private readonly _updateReadyState = () => {
        if (this.isReady()) {
            this.setState(() => ({
                ready: true,
            }));
            clearInterval(this.readyIntervalId);
            if (this.props.onLoad) {
                this.props.onLoad();
            }
        }
    };
}

export default GoogleReCaptcha;
