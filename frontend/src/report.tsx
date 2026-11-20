import { useState, type FormEvent } from 'react'
import { limits, severities, submitReport, type Severity } from './api'

// The public page for external reporters at /report. It works without a login.
export function ReportPage() {
  const [receipt, setReceipt] = useState<{ reference: string; email: string } | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [sending, setSending] = useState(false)

  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    const form = new FormData(event.currentTarget)
    const email = String(form.get('reporterEmail'))
    setSending(true)
    setError(null)
    try {
      const reference = await submitReport({
        title: String(form.get('title')),
        description: String(form.get('description')),
        affectedAsset: String(form.get('affectedAsset')),
        severity: form.get('severity') as Severity,
        reporterEmail: email,
      })
      setReceipt({ reference, email })
    } catch (e) {
      setError((e as Error).message)
      setSending(false)
    }
  }

  return (
    <>
      <header>
        <h1>VulnTrack</h1>
      </header>
      <main>
        {receipt ? (
          <article>
            <h2>Thank you for your report</h2>
            <p>We have received it and will look into it. If we need more information, we will contact you at {receipt.email}.</p>
            <p>
              Your reference is <code>{receipt.reference}</code>. Keep it, so you can tell which report we are writing
              about.
            </p>
          </article>
        ) : (
          <form onSubmit={submit}>
            <h2>Report a vulnerability</h2>
            <p className="muted">
              Found a security issue in one of our systems? Tell us about it here. You don't need an account. We only
              use your email to contact you about this report.
            </p>
            <label>
              Title
              <input name="title" required maxLength={limits.title} />
            </label>
            <label>
              Affected system
              <input name="affectedAsset" required maxLength={limits.affectedAsset} />
            </label>
            <label>
              How severe do you think it is?
              <select name="severity" required defaultValue="Medium">
                {severities.map((severity) => (
                  <option key={severity}>{severity}</option>
                ))}
              </select>
            </label>
            <label>
              Description and steps to reproduce
              <textarea name="description" required maxLength={limits.description} rows={8} />
            </label>
            <label>
              Your email
              <input name="reporterEmail" type="email" required maxLength={limits.email} autoComplete="email" />
            </label>
            {error && <p role="alert">{error}</p>}
            <div className="actions">
              <button type="submit" className="primary" disabled={sending}>
                Send report
              </button>
            </div>
          </form>
        )}
      </main>
    </>
  )
}
