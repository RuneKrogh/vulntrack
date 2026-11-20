import { useEffect, useState } from 'react'
import { getAudit, statusLabels, type AuditChange, type AuditEntry, type FindingStatus } from './api'

const fieldLabels: Record<string, string> = {
  Title: 'title',
  AffectedAsset: 'asset',
  Severity: 'severity',
  Status: 'status',
  AssigneeName: 'assignee',
  DueDate: 'due date',
  DiscoveredAt: 'discovery date',
  Description: 'description',
}

function formatValue(field: string, value: string | null): string {
  if (value === null) return 'none'
  return field === 'Status' ? (statusLabels[value as FindingStatus] ?? value) : value
}

function describeChange(change: AuditChange): string {
  const label = fieldLabels[change.field] ?? change.field
  // The log doesn't hold the description text, only that it changed.
  if (change.field === 'Description') return 'edited the description'
  return `${label} ${formatValue(change.field, change.from)} → ${formatValue(change.field, change.to)}`
}

function describe(entry: AuditEntry): string {
  if (entry.action === 'Created') return 'created the finding'
  // The assignee's name is shown, so the id next to it adds nothing here.
  return entry.changes
    .filter((change) => change.field !== 'AssigneeId')
    .map(describeChange)
    .join(', ')
}

type AuditListProps = {
  // Without a finding the list shows every change, with the title of the finding it belongs to.
  findingId?: string
  // Loads the list again when this changes, for example after the finding was edited.
  refresh?: unknown
}

export function AuditList({ findingId, refresh }: AuditListProps) {
  const [entries, setEntries] = useState<AuditEntry[]>([])
  const [next, setNext] = useState<number | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [loading, setLoading] = useState(false)

  useEffect(() => {
    getAudit(findingId, null)
      .then((page) => {
        setEntries(page.entries)
        setNext(page.next)
      })
      .catch((e: Error) => setError(e.message))
  }, [findingId, refresh])

  async function loadOlder() {
    setLoading(true)
    try {
      const page = await getAudit(findingId, next)
      setEntries([...entries, ...page.entries])
      setNext(page.next)
    } catch (e) {
      setError((e as Error).message)
    }
    setLoading(false)
  }

  if (error) return <p role="alert">{error}</p>
  if (entries.length === 0) return <p className="muted">No changes recorded.</p>

  return (
    <>
      <ul className="audit">
        {entries.map((entry) => (
          <li key={entry.sequence}>
            <span className="muted">{new Date(entry.at).toLocaleString()}</span> {entry.actorName}{' '}
            {findingId === undefined && (
              <>
                on <strong>{entry.findingTitle}</strong>:{' '}
              </>
            )}
            {describe(entry)}
          </li>
        ))}
      </ul>
      {next !== null && (
        <button onClick={loadOlder} disabled={loading}>
          Load older changes
        </button>
      )}
    </>
  )
}
