import { useEffect, useState, type FormEvent } from 'react'
import {
  assignFinding,
  createFinding,
  getAssignees,
  limits,
  severities,
  statusLabels,
  type Assignee,
  type Finding,
  type FindingFilter,
  type FindingStatus,
  type Severity,
} from './api'

// The backend compares dates against the UTC date, so the forms do the same.
const todayUtc = () => new Date().toISOString().slice(0, 10)

type FilterBarProps = {
  filter: FindingFilter
  showOwner: boolean
  onChange: (filter: FindingFilter) => void
}

export function FilterBar({ filter, showOwner, onChange }: FilterBarProps) {
  const [search, setSearch] = useState(filter.q)
  const [assignees, setAssignees] = useState<Assignee[]>([])
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    if (!showOwner) return
    getAssignees()
      .then(setAssignees)
      .catch((e: Error) => setError(e.message))
  }, [showOwner])

  // The search is sent once typing pauses, not on every key.
  useEffect(() => {
    if (search === filter.q) return
    const timer = setTimeout(() => onChange({ ...filter, q: search }), 300)
    return () => clearTimeout(timer)
  }, [search, filter, onChange])

  return (
    <div className="filters">
      <label className="search">
        Search title or asset
        <input type="search" value={search} maxLength={limits.title} onChange={(e) => setSearch(e.target.value)} />
      </label>
      <label>
        Status
        <select value={filter.status} onChange={(e) => onChange({ ...filter, status: e.target.value as FindingStatus | '' })}>
          <option value="">All</option>
          {Object.entries(statusLabels).map(([status, label]) => (
            <option key={status} value={status}>
              {label}
            </option>
          ))}
        </select>
      </label>
      <label>
        Severity
        <select value={filter.severity} onChange={(e) => onChange({ ...filter, severity: e.target.value as Severity | '' })}>
          <option value="">All</option>
          {severities.map((severity) => (
            <option key={severity}>{severity}</option>
          ))}
        </select>
      </label>
      {showOwner && (
        <label>
          Owner
          <select value={filter.assigneeId} onChange={(e) => onChange({ ...filter, assigneeId: e.target.value })}>
            <option value="">All</option>
            <option value="none">Unassigned</option>
            {assignees.map((assignee) => (
              <option key={assignee.id} value={assignee.id}>
                {assignee.name}
              </option>
            ))}
          </select>
        </label>
      )}
      {error && <p role="alert">{error}</p>}
    </div>
  )
}

type FindingListProps = {
  findings: Finding[]
  filtered: boolean
  onOpen: (finding: Finding) => void
}

export function FindingList({ findings, filtered, onOpen }: FindingListProps) {
  if (findings.length === 0) return <p>{filtered ? 'No findings match the filters.' : 'No findings yet.'}</p>

  return (
    <table>
      <thead>
        <tr>
          <th>Title</th>
          <th>Asset</th>
          <th>Severity</th>
          <th>Status</th>
          <th>Assignee</th>
          <th>Due</th>
          <th>Discovered</th>
        </tr>
      </thead>
      <tbody>
        {findings.map((finding) => (
          <tr key={finding.id} onClick={() => onOpen(finding)}>
            <td>{finding.title}</td>
            <td>{finding.affectedAsset}</td>
            <td>{finding.severity}</td>
            <td>{statusLabels[finding.status]}</td>
            <td>{finding.assigneeName ?? '–'}</td>
            <td>{finding.dueDate ?? '–'}</td>
            <td>{finding.discoveredAt}</td>
          </tr>
        ))}
      </tbody>
    </table>
  )
}

type FindingDetailsProps = {
  finding: Finding
  canAssign: boolean
  onChanged: (finding: Finding) => void
  onBack: () => void
}

export function FindingDetails({ finding, canAssign, onChanged, onBack }: FindingDetailsProps) {
  return (
    <article>
      <button onClick={onBack}>Back</button>
      <h2>{finding.title}</h2>
      <dl>
        <dt>Asset</dt>
        <dd>{finding.affectedAsset}</dd>
        <dt>Severity</dt>
        <dd>{finding.severity}</dd>
        <dt>Status</dt>
        <dd>{statusLabels[finding.status]}</dd>
        <dt>Assignee</dt>
        <dd>{finding.assigneeName ?? 'Not assigned'}</dd>
        <dt>Due</dt>
        <dd>{finding.dueDate ?? '–'}</dd>
        <dt>Discovered</dt>
        <dd>{finding.discoveredAt}</dd>
        {/* Plain text and not a mailto link, so a crafted address can't fill in recipients or text in a mail client. */}
        {finding.reporterEmail && (
          <>
            <dt>Reported by</dt>
            <dd>{finding.reporterEmail}</dd>
          </>
        )}
      </dl>
      <p className="description">{finding.description}</p>
      {canAssign && <AssignForm finding={finding} onAssigned={onChanged} />}
    </article>
  )
}

function AssignForm({ finding, onAssigned }: { finding: Finding; onAssigned: (finding: Finding) => void }) {
  const [assignees, setAssignees] = useState<Assignee[]>([])
  const [error, setError] = useState<string | null>(null)
  const [saving, setSaving] = useState(false)
  const [today] = useState(todayUtc)

  useEffect(() => {
    getAssignees()
      .then(setAssignees)
      .catch((e: Error) => setError(e.message))
  }, [])

  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    const form = new FormData(event.currentTarget)
    setSaving(true)
    setError(null)
    try {
      onAssigned(await assignFinding(finding.id, String(form.get('assigneeId')), String(form.get('dueDate'))))
    } catch (e) {
      setError((e as Error).message)
    }
    setSaving(false)
  }

  return (
    <form onSubmit={submit}>
      <h2>Assign</h2>
      <label>
        Developer
        {/* The key makes the dropdown pick up the current assignee once the list has loaded. */}
        <select name="assigneeId" required defaultValue={finding.assigneeId ?? ''} key={assignees.length}>
          <option value="" disabled>
            Choose a developer
          </option>
          {assignees.map((assignee) => (
            <option key={assignee.id} value={assignee.id}>
              {assignee.name}
            </option>
          ))}
        </select>
      </label>
      <label>
        Due date
        <input name="dueDate" type="date" required min={today} defaultValue={finding.dueDate ?? ''} />
      </label>
      {error && <p role="alert">{error}</p>}
      <div className="actions">
        <button type="submit" className="primary" disabled={saving}>
          Save assignment
        </button>
      </div>
    </form>
  )
}

export function FindingForm({ onSaved, onCancel }: { onSaved: (finding: Finding) => void; onCancel: () => void }) {
  const [error, setError] = useState<string | null>(null)
  const [saving, setSaving] = useState(false)
  const [today] = useState(todayUtc)

  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    const form = new FormData(event.currentTarget)
    setSaving(true)
    setError(null)
    try {
      onSaved(
        await createFinding({
          title: String(form.get('title')),
          description: String(form.get('description')),
          affectedAsset: String(form.get('affectedAsset')),
          severity: form.get('severity') as Severity,
          discoveredAt: String(form.get('discoveredAt')),
        }),
      )
    } catch (e) {
      setError((e as Error).message)
      setSaving(false)
    }
  }

  return (
    <form onSubmit={submit}>
      <h2>New finding</h2>
      <label>
        Title
        <input name="title" required maxLength={limits.title} />
      </label>
      <label>
        Affected asset
        <input name="affectedAsset" required maxLength={limits.affectedAsset} />
      </label>
      <label>
        Severity
        <select name="severity" required defaultValue="Medium">
          {severities.map((severity) => (
            <option key={severity}>{severity}</option>
          ))}
        </select>
      </label>
      <label>
        Discovered
        <input name="discoveredAt" type="date" required max={today} defaultValue={today} />
      </label>
      <label>
        Description
        <textarea name="description" required maxLength={limits.description} rows={8} />
      </label>
      {error && <p role="alert">{error}</p>}
      <div className="actions">
        <button type="submit" className="primary" disabled={saving}>
          Save
        </button>
        <button type="button" onClick={onCancel}>
          Cancel
        </button>
      </div>
    </form>
  )
}
