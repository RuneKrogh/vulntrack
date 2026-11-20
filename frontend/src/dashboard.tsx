import { severities, statusLabels, type Dashboard, type FindingStatus } from './api'

export function DashboardSummary({ dashboard }: { dashboard: Dashboard }) {
  return (
    <div className="dashboard">
      <section>
        <h2>Open by severity</h2>
        <table>
          <tbody>
            {/* Most severe first. */}
            {[...severities].reverse().map((severity) => (
              <tr key={severity}>
                <td>{severity}</td>
                <td className="count">{dashboard.openBySeverity[severity]}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </section>
      <section>
        <h2>By status</h2>
        <table>
          <tbody>
            {(Object.keys(statusLabels) as FindingStatus[]).map((status) => (
              <tr key={status}>
                <td>{statusLabels[status]}</td>
                <td className="count">{dashboard.byStatus[status]}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </section>
      <section>
        <h2>Due dates</h2>
        <p className={dashboard.overdue > 0 ? 'overdue' : undefined}>
          {dashboard.overdue} of {dashboard.openWithDueDate} open findings with a due date are overdue.
        </p>
      </section>
    </div>
  )
}
