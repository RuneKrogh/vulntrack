export type CurrentUser = {
  name: string
  roles: string[]
}

export const severities = ['Low', 'Medium', 'High', 'Critical'] as const
export type Severity = (typeof severities)[number]

export type FindingStatus = 'New' | 'Triaged' | 'InProgress' | 'Remediated' | 'AcceptedRisk'

export const statusLabels: Record<FindingStatus, string> = {
  New: 'New',
  Triaged: 'Triaged',
  InProgress: 'In progress',
  Remediated: 'Remediated',
  AcceptedRisk: 'Accepted risk',
}

export type Finding = {
  id: string
  title: string
  description: string
  affectedAsset: string
  severity: Severity
  discoveredAt: string
  status: FindingStatus
  assigneeId: string | null
  assigneeName: string | null
  dueDate: string | null
  // Only sent to analysts and PMs, and only for findings from the public report form.
  reporterEmail: string | null
}

// The details that can be edited after a finding is created.
export type EditableFields = Pick<Finding, 'title' | 'description' | 'affectedAsset' | 'severity'>

export type NewFinding = EditableFields & Pick<Finding, 'discoveredAt'>

// Counts over the findings the user may see. Open means not remediated and not accepted.
export type Dashboard = {
  openBySeverity: Record<Severity, number>
  byStatus: Record<FindingStatus, number>
  openWithDueDate: number
  overdue: number
}

// Empty values mean no filter and are left out of the request.
export type FindingFilter = {
  q: string
  status: FindingStatus | ''
  severity: Severity | ''
  // A developer's id, or "none" for unassigned findings.
  assigneeId: string
}

export const noFilter: FindingFilter = { q: '', status: '', severity: '', assigneeId: '' }

export type NewReport = Pick<Finding, 'title' | 'description' | 'affectedAsset' | 'severity'> & { reporterEmail: string }

export type Assignee = {
  id: string
  name: string
}

// Same limits as the backend, so the forms stop input the API would reject anyway.
export const limits = { title: 256, description: 8192, affectedAsset: 256, email: 254 }

// Every request carries the X-CSRF header, which the backend requires on state-changing API calls.
async function request(path: string, init: RequestInit = {}): Promise<Response> {
  const headers = new Headers(init.headers)
  headers.set('X-CSRF', '1')
  return fetch(path, { ...init, headers, credentials: 'same-origin' })
}

// Turns a failed response into an error with a readable message, using the validation errors when there are any.
async function failure(response: Response, action: string): Promise<Error> {
  const problem = (await response.json().catch(() => null)) as { errors?: Record<string, string[]> } | null
  const details = problem?.errors ? Object.values(problem.errors).flat().join(' ') : `status ${response.status}`
  return new Error(`${action} failed: ${details}`)
}

export async function getCurrentUser(): Promise<CurrentUser | null> {
  const response = await request('/api/me')
  if (response.status === 401) return null
  if (!response.ok) throw await failure(response, 'Loading the current user')
  return response.json()
}

// The backend ends the session and returns the Keycloak logout URL to finish the logout there.
export async function logout(): Promise<void> {
  const response = await request('/api/auth/logout', { method: 'POST' })
  if (!response.ok) throw await failure(response, 'Logout')
  const { url } = (await response.json()) as { url: string }
  window.location.assign(url)
}

export async function getFindings(filter: FindingFilter, signal: AbortSignal): Promise<Finding[]> {
  const params = new URLSearchParams()
  for (const [key, value] of Object.entries(filter)) {
    if (value) params.set(key, value)
  }
  const query = params.toString()
  const response = await request(query ? `/api/findings?${query}` : '/api/findings', { signal })
  if (!response.ok) throw await failure(response, 'Loading findings')
  return response.json()
}

export async function createFinding(finding: NewFinding): Promise<Finding> {
  const response = await request('/api/findings', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(finding),
  })
  if (!response.ok) throw await failure(response, 'Saving the finding')
  return response.json()
}

export async function getDashboard(): Promise<Dashboard> {
  const response = await request('/api/dashboard')
  if (!response.ok) throw await failure(response, 'Loading the dashboard')
  return response.json()
}

// Public, no login needed. Returns the reference the reporter gets as acknowledgement.
export async function submitReport(report: NewReport): Promise<string> {
  const response = await request('/api/reports', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(report),
  })
  if (response.status === 429) {
    throw new Error('Too many reports from your network. Please try again in a few minutes.')
  }
  if (!response.ok) throw await failure(response, 'Sending the report')
  const { reference } = (await response.json()) as { reference: string }
  return reference
}

export async function editFinding(id: string, fields: EditableFields): Promise<Finding> {
  const response = await request(`/api/findings/${encodeURIComponent(id)}`, {
    method: 'PUT',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(fields),
  })
  if (response.status === 403) throw new Error('You are not allowed to change the severity.')
  if (!response.ok) throw await failure(response, 'Saving the finding')
  return response.json()
}

export async function updateStatus(id: string, status: FindingStatus): Promise<Finding> {
  const response = await request(`/api/findings/${encodeURIComponent(id)}/status`, {
    method: 'PUT',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ status }),
  })
  if (response.status === 403) throw new Error('You are not allowed to set this status.')
  if (!response.ok) throw await failure(response, 'Changing the status')
  return response.json()
}

export async function getAssignees(): Promise<Assignee[]> {
  const response = await request('/api/assignees')
  if (!response.ok) throw await failure(response, 'Loading developers')
  return response.json()
}

export async function assignFinding(id: string, assigneeId: string, dueDate: string): Promise<Finding> {
  const response = await request(`/api/findings/${encodeURIComponent(id)}/assignment`, {
    method: 'PUT',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ assigneeId, dueDate }),
  })
  if (!response.ok) throw await failure(response, 'Assigning the finding')
  return response.json()
}
