import { NavLink, Outlet } from 'react-router-dom';

const NAV_ITEMS = [
  { to: '/', label: 'Dashboard', end: true },
  { to: '/secure-access', label: 'Secure File Access' },
  { to: '/scans/new', label: 'New Scan' },
  { to: '/scans', label: 'Scan History' },
];

export function Layout() {
  return (
    <div className="app">
      <header className="topbar">
        <div className="topbar-inner">
          <NavLink to="/" className="brand" aria-label="SANDBox home">
            <span className="brand-mark" aria-hidden="true">
              S
            </span>
            <span className="brand-text">
              <span className="brand-name">SANDBox</span>
              <span className="brand-sub">Secure Document Gateway</span>
            </span>
          </NavLink>
          <nav className="nav" aria-label="Main navigation">
            <ul className="nav-list">
              {NAV_ITEMS.map((item) => (
                <li key={item.to}>
                  <NavLink
                    to={item.to}
                    end={item.end}
                    className={({ isActive }) => (isActive ? 'nav-link active' : 'nav-link')}
                  >
                    {item.label}
                  </NavLink>
                </li>
              ))}
            </ul>
          </nav>
        </div>
      </header>

      <main className="main" id="main">
        <Outlet />
      </main>

      <footer className="footer">
        <span>SANDBox - secure file access gateway</span>
        <span className="footer-muted">Deterministic analysis engine. Verdicts are produced by the backend; access is fail-closed.</span>
      </footer>
    </div>
  );
}