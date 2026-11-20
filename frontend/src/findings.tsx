import { useState, type FormEvent } from 'react'
import { createFinding, limits, severities, type Finding, type FindingStatus, type Severity } from './api'

const statusLabels: Record<FindingStatus, string> = {
  New: 'New',
  Triaged: 'Triaged',
  InProgress: 'In progress',
  Remediated: 'Remediated',
  AcceptedRisk: 'Accepted risk',
}

export function FindingList({ findings, onOpen }: { findings: Finding[]; onOpen: (finding: Finding) => void }) {
  if (findings.length === 0) return <p>No findings yet.</p>

  return (
    <table>
      <thead>
        <tr>
          <th>Title</th>
          <th>Asset</th>
          <th>Severity</th>
          <th>Status</th>
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
            <td>{finding.discoveredAt}</td>
          </tr>
        ))}
      </tbody>
    </table>
  )
}

export function FindingDetails({ finding, onBack }: { finding: Finding; onBack: () => void }) {
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
        <dt>Discovered</dt>
        <dd>{finding.discoveredAt}</dd>
      </dl>
      <p className="description">{finding.description}</p>
    </article>
  )
}

export function FindingForm({ onSaved, onCancel }: { onSaved: (finding: Finding) => void; onCancel: () => void }) {
  const [error, setError] = useState<string | null>(null)
  const [saving, setSaving] = useState(false)
  // The backend compares against the UTC date, so the form does the same.
  const [today] = useState(() => new Date().toISOString().slice(0, 10))

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
