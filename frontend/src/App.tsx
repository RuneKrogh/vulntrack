import { useEffect, useState } from 'react'
import { getCurrentUser, getFindings, logout, type CurrentUser, type Finding } from './api'
import { FindingDetails, FindingForm, FindingList } from './findings'

type View = { name: 'list' } | { name: 'details'; finding: Finding } | { name: 'new' }

export default function App() {
  const [user, setUser] = useState<CurrentUser | null | undefined>(undefined)
  const [findings, setFindings] = useState<Finding[]>([])
  const [view, setView] = useState<View>({ name: 'list' })
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    getCurrentUser()
      .then(async (current) => {
        setUser(current)
        if (current) setFindings(await getFindings())
      })
      .catch((e: Error) => setError(e.message))
  }, [])

  // Only hides the button. The backend decides who may actually create findings.
  const canCreate = user?.roles.some((role) => role === 'analyst' || role === 'pm') ?? false

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
        {user === null && <p>Log in to see and manage findings.</p>}
        {user && view.name === 'list' && (
          <>
            <div className="toolbar">
              <h2>Findings</h2>
              {canCreate && (
                <button className="primary" onClick={() => setView({ name: 'new' })}>
                  New finding
                </button>
              )}
            </div>
            <FindingList findings={findings} onOpen={(finding) => setView({ name: 'details', finding })} />
          </>
        )}
        {user && view.name === 'details' && (
          <FindingDetails finding={view.finding} onBack={() => setView({ name: 'list' })} />
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
