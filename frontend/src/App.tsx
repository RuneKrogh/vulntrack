import { useEffect, useState } from 'react'
import { getCurrentUser, logout, type CurrentUser } from './api'

export default function App() {
  const [user, setUser] = useState<CurrentUser | null | undefined>(undefined)
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    getCurrentUser()
      .then(setUser)
      .catch((e: Error) => setError(e.message))
  }, [])

  return (
    <>
      <header>
        <h1>VulnTrack</h1>
        {user ? (
          <button onClick={() => logout().catch((e: Error) => setError(e.message))}>Log out</button>
        ) : (
          user === null && (
            <a className="button" href="/auth/login">
              Log in
            </a>
          )
        )}
      </header>
      <main>
        {error && <p role="alert">{error}</p>}
        {user && (
          <p>
            Signed in as <strong>{user.name}</strong> ({user.roles.join(', ') || 'no roles'})
          </p>
        )}
        {user === null && <p>Log in to see and manage findings.</p>}
      </main>
    </>
  )
}
