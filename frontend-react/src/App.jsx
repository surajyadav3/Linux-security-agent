import { useState, useEffect, useCallback } from 'react'
import './index.css'

const DEFAULT_API = import.meta.env.VITE_API_URL || 'https://1l2m6dkgqf.execute-api.ap-south-1.amazonaws.com/prod'

function fmtTime(iso) {
  if (!iso) return '–'
  try { return new Date(iso).toLocaleString() } catch { return iso }
}

function makeFetcher(apiUrl) {
  return async (path) => {
    const res = await fetch(apiUrl.replace(/\/$/, '') + path)
    if (!res.ok) throw new Error(`HTTP ${res.status}`)
    return res.json()
  }
}

function HostCard({ host, selected, onClick }) {
  const pass = Number(host.cis_pass || 0)
  const total = Number(host.cis_total || 1)
  const pct = Math.round((pass / total) * 100)
  const scoreClass = pct >= 80 ? 'score-good' : pct >= 60 ? 'score-warn' : 'score-bad'

  return (
    <div className={`host-card${selected ? ' selected' : ''}`} onClick={onClick}>
      <div className="name">{host.agent_id}</div>
      <div className="meta">
        {host.host?.os} &bull; {host.host?.kernel} &bull; Last: {fmtTime(host.timestamp)}
      </div>
      <div className="row">
        <span>{host.package_count || 0} packages</span>
        <span>{pass}/{total} CIS checks</span>
      </div>
      <div className="score-bar">
        <div className={`score-fill ${scoreClass}`} style={{ width: `${pct}%` }} />
      </div>
    </div>
  )
}

function CISTab({ checks }) {
  const counts = {}
  checks.forEach(c => { counts[c.status] = (counts[c.status] || 0) + 1 })

  return (
    <>
      <div className="summary-bar">
        {Object.entries(counts).map(([k, v]) => (
          <span key={k} className={`badge badge-${k.toLowerCase()}`}>{v} {k}</span>
        ))}
      </div>
      <table>
        <thead>
          <tr><th>ID</th><th>Check</th><th>Severity</th><th>Status</th><th>Evidence</th></tr>
        </thead>
        <tbody>
          {checks.map((c, i) => (
            <tr key={i}>
              <td style={{ whiteSpace: 'nowrap', color: '#64748b' }}>{c.id}</td>
              <td>{c.title}</td>
              <td className={`sev-${c.severity?.toLowerCase()}`}>{c.severity}</td>
              <td><span className={`status-chip status-${c.status}`}>{c.status}</span></td>
              <td className="evidence">{c.evidence}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </>
  )
}

function PackagesTab({ packages }) {
  const [query, setQuery] = useState('')
  const q = query.toLowerCase()
  const filtered = q
    ? packages.filter(p => p.name.toLowerCase().includes(q) || (p.version || '').toLowerCase().includes(q))
    : packages

  return (
    <>
      <div className="search-bar">
        <input
          type="text"
          placeholder="Search packages..."
          value={query}
          onChange={e => setQuery(e.target.value)}
        />
        <span className="pkg-count">{filtered.length} packages</span>
      </div>
      <table>
        <thead>
          <tr><th>#</th><th>Package</th><th>Version</th><th>Arch</th></tr>
        </thead>
        <tbody>
          {filtered.map((p, i) => (
            <tr key={i}>
              <td style={{ color: '#64748b' }}>{i + 1}</td>
              <td>{p.name}</td>
              <td>{p.version}</td>
              <td>{p.arch || ''}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </>
  )
}

function DetailView({ agentId, fetcher }) {
  const [activeTab, setActiveTab] = useState('cis')
  const [cisData, setCisData] = useState(null)
  const [pkgData, setPkgData] = useState(null)

  useEffect(() => {
    setCisData(null)
    setPkgData(null)
    fetcher(`/cis-results/${agentId}`).then(setCisData).catch(() => null)
    fetcher(`/apps/${agentId}`).then(setPkgData).catch(() => null)
  }, [agentId, fetcher])

  return (
    <div>
      <div className="detail-header">
        <h2>{agentId}</h2>
        {cisData && (
          <span className="detail-os">
            {cisData.host?.os} {cisData.host?.os_version} — {cisData.host?.arch}
          </span>
        )}
      </div>
      <div className="tabs">
        <button className={`tab${activeTab === 'cis' ? ' active' : ''}`} onClick={() => setActiveTab('cis')}>CIS Checks</button>
        <button className={`tab${activeTab === 'packages' ? ' active' : ''}`} onClick={() => setActiveTab('packages')}>Packages</button>
      </div>
      {activeTab === 'cis' && (cisData ? <CISTab checks={cisData.cis_checks || []} /> : <div className="placeholder">Loading...</div>)}
      {activeTab === 'packages' && (pkgData ? <PackagesTab packages={pkgData.packages || []} /> : <div className="placeholder">Loading...</div>)}
    </div>
  )
}

export default function App() {
  const [apiUrl, setApiUrl] = useState(DEFAULT_API)
  const [hosts, setHosts] = useState(null)
  const [error, setError] = useState(null)
  const [lastUpdated, setLastUpdated] = useState(null)
  const [selectedHost, setSelectedHost] = useState(null)

  const fetcher = useCallback(() => makeFetcher(apiUrl), [apiUrl])()

  async function loadHosts(url) {
    const fetch = makeFetcher(url || apiUrl)
    setError(null)
    setHosts(null)
    setSelectedHost(null)
    try {
      const data = await fetch('/hosts')
      setHosts(data.sort((a, b) => (b.timestamp || '').localeCompare(a.timestamp || '')))
      setLastUpdated(new Date().toLocaleTimeString())
    } catch (e) {
      setError(e.message)
    }
  }

  useEffect(() => { loadHosts() }, [])

  return (
    <>
      <header>
        <div className="header-inner">
          <h1>&#x1F6E1; Linux Security Agent</h1>
          <span className="last-updated">{lastUpdated ? `Updated ${lastUpdated}` : 'Loading...'}</span>
        </div>
      </header>
      <main>
        <div className="config-bar">
          <input
            type="text"
            value={apiUrl}
            onChange={e => setApiUrl(e.target.value)}
            placeholder="https://xxxx.execute-api.us-east-1.amazonaws.com/prod"
            onKeyDown={e => e.key === 'Enter' && loadHosts(apiUrl)}
          />
          <button onClick={() => loadHosts(apiUrl)}>Connect</button>
        </div>

        <section>
          <h2 className="section-title">Hosts</h2>
          <div className="card-grid">
            {hosts === null && !error && <div className="placeholder">Loading...</div>}
            {error && <div className="placeholder" style={{ color: '#f87171' }}>Error: {error}</div>}
            {hosts?.length === 0 && <div className="placeholder">No agents have reported in yet.</div>}
            {hosts?.map(h => (
              <HostCard
                key={h.agent_id}
                host={h}
                selected={selectedHost === h.agent_id}
                onClick={() => setSelectedHost(h.agent_id)}
              />
            ))}
          </div>
        </section>

        {selectedHost && <DetailView agentId={selectedHost} fetcher={fetcher} />}
      </main>
    </>
  )
}
