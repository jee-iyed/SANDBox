import type { ReactNode } from 'react';

type AlertVariant = 'error' | 'warning' | 'info' | 'success';

interface AlertProps {
  variant: AlertVariant;
  title?: string;
  children: ReactNode;
}

export function Alert({ variant, title, children }: AlertProps) {
  return (
    <div className={`alert alert-${variant}`} role="alert">
      <div className="alert-body">
        {title && <div className="alert-title">{title}</div>}
        <div className="alert-message">{children}</div>
      </div>
    </div>
  );
}