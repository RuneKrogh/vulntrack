export type CurrentUser = {
  name: string
  roles: string[]
}

// Every request carries the X-CSRF header, which the backend requires on state-changing API calls.
async function request(path: string, init: RequestInit = {}): Promise<Response> {
  const headers = new Headers(init.headers)
  headers.set('X-CSRF', '1')
  return fetch(path, { ...init, headers, credentials: 'same-origin' })
}

export async function getCurrentUser(): Promise<CurrentUser | null> {
  const response = await request('/api/me')
  if (response.status === 401) return null
  if (!response.ok) throw new Error(`Could not load the current user (${response.status})`)
  return response.json()
}

// The backend ends the session and returns the Keycloak logout URL to finish the logout there.
export async function logout(): Promise<void> {
  const response = await request('/api/auth/logout', { method: 'POST' })
  if (!response.ok) throw new Error(`Logout failed (${response.status})`)
  const { url } = (await response.json()) as { url: string }
  window.location.assign(url)
}
