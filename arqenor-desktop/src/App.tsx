import { Routes, Route, Navigate } from 'react-router-dom'
import Layout from './components/Layout'
import Dashboard   from './pages/Dashboard'
import Alerts      from './pages/Alerts'
import EtwStream   from './pages/EtwStream'
import Processes   from './pages/Processes'
import Network     from './pages/Network'
import Persistence from './pages/Persistence'
import Incidents       from './pages/Incidents'
import MemoryForensics from './pages/MemoryForensics'
import IocDatabase     from './pages/IocDatabase'

export default function App() {
  return (
    <Layout>
      <Routes>
        <Route path="/"            element={<Navigate to="/dashboard" replace />} />
        <Route path="/dashboard"   element={<Dashboard />} />
        <Route path="/alerts"      element={<Alerts />} />
        <Route path="/etw"         element={<EtwStream />} />
        <Route path="/processes"   element={<Processes />} />
        <Route path="/network"     element={<Network />} />
        <Route path="/persistence" element={<Persistence />} />
        <Route path="/incidents"   element={<Incidents />} />
        <Route path="/memory"      element={<MemoryForensics />} />
        <Route path="/ioc"         element={<IocDatabase />} />
      </Routes>
    </Layout>
  )
}
