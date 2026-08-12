import { useEffect, useState } from "react";
import { api, NotificationLogEntry, ReminderSettings } from "../api/client";
import StatusPill from "../components/StatusPill";

function toCommaList(values: string[]): string {
  return values.join(", ");
}

function fromCommaList(text: string): string[] {
  return text
    .split(",")
    .map((v) => v.trim())
    .filter(Boolean);
}

export default function NotificationSettings() {
  const [settings, setSettings] = useState<ReminderSettings | null>(null);
  const [history, setHistory] = useState<NotificationLogEntry[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [saved, setSaved] = useState(false);
  const [saving, setSaving] = useState(false);

  const [thresholds, setThresholds] = useState("");
  const [subjectTpl, setSubjectTpl] = useState("");
  const [bodyTpl, setBodyTpl] = useState("");
  const [defaultRecipients, setDefaultRecipients] = useState("");
  const [escalationRecipients, setEscalationRecipients] = useState("");

  function load() {
    api
      .getNotificationSettings()
      .then((s) => {
        setSettings(s);
        setThresholds(s.threshold_days.join(", "));
        setSubjectTpl(s.email_subject_template);
        setBodyTpl(s.email_body_template);
        setDefaultRecipients(toCommaList(s.default_recipients ?? []));
        setEscalationRecipients(toCommaList(s.escalation_recipients ?? []));
      })
      .catch((e) => setError(e.message));
    api
      .listRecentNotifications(50)
      .then((h) => setHistory(h ?? []))
      .catch((e) => setError(e.message));
  }

  useEffect(load, []);

  async function save() {
    if (!settings) return;
    setError(null);
    setSaving(true);
    setSaved(false);
    try {
      const thresholdDays = thresholds
        .split(",")
        .map((v) => Number(v.trim()))
        .filter((v) => !Number.isNaN(v) && v > 0)
        .sort((a, b) => b - a);
      const updated = await api.updateNotificationSettings({
        threshold_days: thresholdDays,
        email_subject_template: subjectTpl,
        email_body_template: bodyTpl,
        default_recipients: fromCommaList(defaultRecipients),
        escalation_recipients: fromCommaList(escalationRecipients),
      });
      setSettings(updated);
      setSaved(true);
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setSaving(false);
    }
  }

  if (error && !settings) return <div className="card">Could not load notification settings: {error}</div>;
  if (!settings) return <p>Loading…</p>;

  return (
    <>
      <h1>Notification settings</h1>
      <p className="page-lede">
        Expiry reminders fire once per certificate per threshold — the most urgent threshold (the smallest number of days) also reaches the
        escalation list. A certificate with its own distribution list set overrides the default recipients below.
      </p>

      {error && <div className="card">{error}</div>}

      <div className="card">
        <div className="field">
          <label>Threshold days (comma-separated)</label>
          <input value={thresholds} onChange={(e) => setThresholds(e.target.value)} placeholder="30, 15, 7, 1" />
        </div>
        <div className="field">
          <label>Email subject template</label>
          <input value={subjectTpl} onChange={(e) => setSubjectTpl(e.target.value)} />
        </div>
        <div className="field">
          <label>Email body template</label>
          <textarea rows={3} value={bodyTpl} onChange={(e) => setBodyTpl(e.target.value)} />
        </div>
        <p style={{ fontSize: 12.5, color: "var(--muted)" }}>
          Available fields: <code>{"{{.CommonName}}"}</code>, <code>{"{{.Domains}}"}</code>, <code>{"{{.OwningTeam}}"}</code>,{" "}
          <code>{"{{.CAProvider}}"}</code>, <code>{"{{.DaysRemaining}}"}</code>, <code>{"{{.NotAfter}}"}</code>.
        </p>
        <div className="field">
          <label>Default recipients (comma-separated)</label>
          <input value={defaultRecipients} onChange={(e) => setDefaultRecipients(e.target.value)} placeholder="team@example.com" />
        </div>
        <div className="field">
          <label>Escalation recipients (comma-separated, most urgent threshold only)</label>
          <input value={escalationRecipients} onChange={(e) => setEscalationRecipients(e.target.value)} placeholder="oncall@example.com" />
        </div>
        <button className="primary" onClick={save} disabled={saving}>
          {saving ? "Saving…" : "Save"}
        </button>
        {saved && <span style={{ marginLeft: 10, color: "var(--muted)", fontSize: 13 }}>Saved.</span>}
      </div>

      <div className="card">
        <h3 style={{ marginTop: 0 }}>Recent notifications</h3>
        <table>
          <thead>
            <tr>
              <th>Sent</th>
              <th>Certificate</th>
              <th>Threshold</th>
              <th>Status</th>
              <th>Recipients</th>
            </tr>
          </thead>
          <tbody>
            {history.map((h) => (
              <tr key={h.id}>
                <td>{new Date(h.sent_at).toLocaleString()}</td>
                <td>
                  <code style={{ fontSize: 12.5 }}>{h.certificate_id}</code>
                </td>
                <td>{h.threshold_days}d</td>
                <td>
                  <StatusPill status={h.status} />
                </td>
                <td>{h.recipients.join(", ") || "—"}</td>
              </tr>
            ))}
            {history.length === 0 && (
              <tr>
                <td colSpan={5}>No notifications sent yet.</td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
    </>
  );
}
