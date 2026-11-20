import { useEffect, useState, type FormEvent } from 'react'
import {
  assignFinding,
  createFinding,
  editFinding,
  getAssignees,
  limits,
  severities,
  statusLabels,
  updateStatus,
  type Assignee,
  type Finding,
  type FindingFilter,
  type FindingStatus,
  type Severity,
} from './api'
import { AuditList } from './audit'

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
  canEdit: boolean
  canChangeSeverity: boolean
  canViewAudit: boolean
  settableStatuses: FindingStatus[]
  onChanged: (finding: Finding) => void
  onBack: () => void
}

export function FindingDetails({
  finding,
  canAssign,
  canEdit,
  canChangeSeverity,
  canViewAudit,
  settableStatuses,
  onChanged,
  onBack,
}: FindingDetailsProps) {
  const [editing, setEditing] = useState(false)

  if (editing) {
    return (
      <EditForm
        finding={finding}
        canChangeSeverity={canChangeSeverity}
        onSaved={(changed) => {
          setEditing(false)
          onChanged(changed)
        }}
        onCancel={() => setEditing(false)}
      />
    )
  }

  return (
    <article>
      <div className="actions">
        <button onClick={onBack}>Back</button>
        {canEdit && <button onClick={() => setEditing(true)}>Edit</button>}
      </div>
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
      {settableStatuses.length > 0 && (
        <StatusForm finding={finding} settableStatuses={settableStatuses} onChanged={onChanged} />
      )}
      {canAssign && <AssignForm finding={finding} onAssigned={onChanged} />}
      {canViewAudit && (
        <section>
          <h2>History</h2>
          <AuditList findingId={finding.id} refresh={finding} />
        </section>
      )}
    </article>
  )
}

type StatusFormProps = {
  finding: Finding
  settableStatuses: FindingStatus[]
  onChanged: (finding: Finding) => void
}

function StatusForm({ finding, settableStatuses, onChanged }: StatusFormProps) {
  const [status, setStatus] = useState(finding.status)
  const [error, setError] = useState<string | null>(null)
  const [saving, setSaving] = useState(false)

  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    setSaving(true)
    setError(null)
    try {
      onChanged(await updateStatus(finding.id, status))
    } catch (e) {
      setError((e as Error).message)
    }
    setSaving(false)
  }

  return (
    <form onSubmit={submit}>
      <h2>Status</h2>
      <label>
        Status
        {/* Statuses the user may not set are shown but disabled, so the current one is still visible. */}
        <select value={status} onChange={(e) => setStatus(e.target.value as FindingStatus)}>
          {(Object.keys(statusLabels) as FindingStatus[]).map((option) => (
            <option key={option} value={option} disabled={!settableStatuses.includes(option)}>
              {statusLabels[option]}
            </option>
          ))}
        </select>
      </label>
      {error && <p role="alert">{error}</p>}
      <div className="actions">
        <button type="submit" className="primary" disabled={saving || status === finding.status}>
          Save status
        </button>
      </div>
    </form>
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

// The fields shared by the create and edit forms, with the same limits as the backend.
function DetailFields({ finding, severityLocked = false }: { finding?: Finding; severityLocked?: boolean }) {
  return (
    <>
      <label>
        Title
        <input name="title" required maxLength={limits.title} defaultValue={finding?.title} />
      </label>
      <label>
        Affected asset
        <input name="affectedAsset" required maxLength={limits.affectedAsset} defaultValue={finding?.affectedAsset} />
      </label>
      <label>
        Severity
        <select name="severity" required defaultValue={finding?.severity ?? 'Medium'} disabled={severityLocked}>
          {severities.map((severity) => (
            <option key={severity}>{severity}</option>
          ))}
        </select>
        {severityLocked && <span className="muted">Only analysts and PMs can change the severity.</span>}
      </label>
      <label>
        Description
        <textarea
          name="description"
          required
          maxLength={limits.description}
          rows={8}
          defaultValue={finding?.description}
        />
      </label>
    </>
  )
}

type EditFormProps = {
  finding: Finding
  canChangeSeverity: boolean
  onSaved: (finding: Finding) => void
  onCancel: () => void
}

function EditForm({ finding, canChangeSeverity, onSaved, onCancel }: EditFormProps) {
  const [error, setError] = useState<string | null>(null)
  const [saving, setSaving] = useState(false)

  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    const form = new FormData(event.currentTarget)
    setSaving(true)
    setError(null)
    try {
      onSaved(
        await editFinding(finding.id, {
          title: String(form.get('title')),
          description: String(form.get('description')),
          affectedAsset: String(form.get('affectedAsset')),
          // A disabled field isn't part of the form data, so the current severity is sent unchanged.
          severity: canChangeSeverity ? (form.get('severity') as Severity) : finding.severity,
        }),
      )
    } catch (e) {
      setError((e as Error).message)
      setSaving(false)
    }
  }

  return (
    <form onSubmit={submit}>
      <h2>Edit finding</h2>
      <DetailFields finding={finding} severityLocked={!canChangeSeverity} />
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
      <DetailFields />
      <label>
        Discovered
        <input name="discoveredAt" type="date" required max={today} defaultValue={today} />
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
