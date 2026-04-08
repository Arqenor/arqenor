import { Routes, Route, Navigate } from 'react-router-dom'
import Layout from './components/Layout'
import Dashboard   from './pages/Dashboard'
import Processes   from './pages/Processes'
import Network     from './pages/Network'
import Persistence from './pages/Persistence'

export default function App() {
  return (
    <Layout>
      <Routes>
        <Route path="/"            element={<Navigate to="/dashboard" replace />} />
        <Route path="/dashboard"   element={<Dashboard />} />
        <Route path="/processes"   element={<Processes />} />
        <Route path="/network"     element={<Network />} />
        <Route path="/persistence" element={<Persistence />} />
      </Routes>
    </Layout>
  )
}
