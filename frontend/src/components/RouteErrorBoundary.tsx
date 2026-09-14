import { Component, type ErrorInfo, type ReactNode } from 'react';

type Props = {
  children: ReactNode;
};

type State = {
  error: Error | null;
};

export default class RouteErrorBoundary extends Component<Props, State> {
  state: State = { error: null };

  static getDerivedStateFromError(error: Error): State {
    return { error };
  }

  componentDidCatch(error: Error, info: ErrorInfo) {
    console.error('[route-render-error]', error, info.componentStack);
  }

  private retry = () => {
    this.setState({ error: null });
    window.location.reload();
  };

  render() {
    if (!this.state.error) return this.props.children;
    return (
      <div className="card" role="alert">
        <h2>页面渲染失败</h2>
        <p className="muted">
          数据量较大或接口短暂不可用时可能出现此问题。可以重新加载，后台任务不会被中断。
        </p>
        <pre className="mono">{this.state.error.message}</pre>
        <button className="btn btn-primary" onClick={this.retry}>
          重新加载页面
        </button>
      </div>
    );
  }
}
