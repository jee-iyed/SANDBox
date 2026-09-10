import { Route, Routes } from 'react-router-dom';

import { Layout } from './components/Layout';
import { Dashboard } from './pages/Dashboard';
import { NewScan } from './pages/NewScan';
import { ScanHistory } from './pages/ScanHistory';
import { ScanDetail } from './pages/ScanDetail';
import { SecureFileAccess } from './pages/SecureFileAccess';

export default function App() {
  return (
    <Routes>
      <Route element={<Layout />}>
        <Route path="/" element={<Dashboard />} />
        <Route path="/secure-access" element={<SecureFileAccess />} />
        <Route path="/scans/new" element={<NewScan />} />
        <Route path="/scans" element={<ScanHistory />} />
        <Route path="/scans/:scanId" element={<ScanDetail />} />
        <Route path="*" element={<Dashboard />} />
      </Route>
    </Routes>
  );
}