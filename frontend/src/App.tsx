import { useEffect, useState } from 'react'
import {
  getCurrentUser,
  getDashboard,
  getFindings,
  logout,
  noFilter,
  statusLabels,
  type CurrentUser,
  type Dashboard,
  type Finding,
  type FindingFilter,
  type FindingStatus,
} from './api'
import { DashboardSummary } from './dashboard'
import { FilterBar, FindingDetails, FindingForm, FindingList } from './findings'

type View = { name: 'list' } | { name: 'details'; finding: Finding } | { name: 'new' }

export default function App() {
  const [user, setUser] = useState<CurrentUser | null | undefined>(undefined)
  const [findings, setFindings] = useState<Finding[]>([])
  const [filter, setFilter] = useState<FindingFilter>(noFilter)
  const [dashboard, setDashboard] = useState<Dashboard | null>(null)
  const [view, setView] = useState<View>({ name: 'list' })
  const [error, setError] = useState<string | null>(null)
  const showingList = view.name === 'list'

  useEffect(() => {
    getCurrentUser()
      .then(setUser)
      .catch((e: Error) => setError(e.message))
  }, [])

  // A new filter cancels the request for the previous one, so a slow old response can't replace a newer list.
  useEffect(() => {
    if (!user) return
    const controller = new AbortController()
    getFindings(filter, controller.signal)
      .then(setFindings)
      .catch((e: Error) => {
        if (!controller.signal.aborted) setError(e.message)
      })
    return () => controller.abort()
  }, [user, filter])

  // Loaded again whenever the list is shown, so it includes findings created or assigned in the meantime.
  useEffect(() => {
    if (!user || !showingList) return
    getDashboard()
      .then(setDashboard)
      .catch((e: Error) => setError(e.message))
  }, [user, showingList])

  // Only hides buttons and forms. The backend decides who may actually create and assign findings.
  const canManage = user?.roles.some((role) => role === 'analyst' || role === 'pm') ?? false
  // Developers only see their own findings, so filtering by owner means nothing to them.
  const canFilterByOwner = canManage || (user?.roles.includes('auditor') ?? false)
  // Same rule as the backend: developers may only start and finish work, triage and risk acceptance are for analysts and PMs.
  const settableStatuses: FindingStatus[] = canManage
    ? (Object.keys(statusLabels) as FindingStatus[])
    : user?.roles.includes('developer')
      ? ['InProgress', 'Remediated']
      : []

  function replaceFinding(changed: Finding) {
    setFindings(findings.map((finding) => (finding.id === changed.id ? changed : finding)))
    setView({ name: 'details', finding: changed })
  }

  return (
    <>
      <header>
        <h1>VulnTrack</h1>
        {user ? (
          <div className="actions">
            <span className="muted">
              {user.name} ({user.roles.join(', ') || 'no roles'})
            </span>
            <button onClick={() => logout().catch((e: Error) => setError(e.message))}>Log out</button>
          </div>
        ) : (
          user === null && (
            <a className="button primary" href="/auth/login">
              Log in
            </a>
          )
        )}
      </header>
      <main>
        {error && <p role="alert">{error}</p>}
        {user === null && (
          <>
            <p>Log in to see and manage findings.</p>
            <p>
              Found a vulnerability? <a href="/report">Report it here</a>, no account needed.
            </p>
          </>
        )}
        {user && showingList && (
          <>
            {dashboard && <DashboardSummary dashboard={dashboard} />}
            <div className="toolbar">
              <h2>Findings</h2>
              {canManage && (
                <button className="primary" onClick={() => setView({ name: 'new' })}>
                  New finding
                </button>
              )}
            </div>
            <FilterBar filter={filter} showOwner={canFilterByOwner} onChange={setFilter} />
            <FindingList
              findings={findings}
              filtered={Object.values(filter).some(Boolean)}
              onOpen={(finding) => setView({ name: 'details', finding })}
            />
          </>
        )}
        {user && view.name === 'details' && (
          <FindingDetails
            finding={view.finding}
            canAssign={canManage}
            settableStatuses={settableStatuses}
            onChanged={replaceFinding}
            onBack={() => setView({ name: 'list' })}
          />
        )}
        {user && view.name === 'new' && (
          <FindingForm
            onSaved={(finding) => {
              setFindings([finding, ...findings])
              setView({ name: 'details', finding })
            }}
            onCancel={() => setView({ name: 'list' })}
          />
        )}
      </main>
    </>
  )
}
