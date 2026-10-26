import { useCallback, useEffect, useState } from 'react';
import MaterialIcon from '../MaterialIcon';
import CopyButton from '../CopyButton';

interface SecretEntry {
    id: string;
    name: string;
    description: string;
    createdAt: string;
    updatedAt: string;
}

interface SecretsStatus {
    keyConfigured: boolean;
    keyError: string | null;
    count: number;
    mismatched: number;
}

interface SecretsPanelProps {
    onConfirm: (message: string) => Promise<boolean>;
    onNotify: (message: string, tone?: 'success' | 'error') => void;
}

const NAME_PATTERN = /^[A-Za-z_][A-Za-z0-9_]{0,63}$/;

const inputClass = 'bg-white/[0.05] border border-white/10 rounded-xl px-4 py-3 text-[10px] text-white';
const buttonClass = 'px-4 py-3 bg-white/5 border border-white/10 text-white rounded-xl text-[9px] font-bold uppercase tracking-widest hover:bg-white/10 transition-all focus:outline-none focus-visible:ring-2 focus-visible:ring-white/50 disabled:opacity-40';

const readError = async (res: Response) => {
    try {
        const body = await res.json();
        return body.details || body.error || `Request failed (${res.status})`;
    } catch {
        return `Request failed (${res.status})`;
    }
};

// Values are write-only: the server never sends them back, so editing a
// secret means typing a replacement, not revealing the current value.
const SecretsPanel: React.FC<SecretsPanelProps> = ({ onConfirm, onNotify }) => {
    const [secrets, setSecrets] = useState<SecretEntry[]>([]);
    const [status, setStatus] = useState<SecretsStatus | null>(null);
    const [loading, setLoading] = useState(false);
    const [saving, setSaving] = useState(false);
    const [name, setName] = useState('');
    const [value, setValue] = useState('');
    const [description, setDescription] = useState('');
    const [replacingId, setReplacingId] = useState<string | null>(null);
    const [replacement, setReplacement] = useState('');

    const load = useCallback(async () => {
        setLoading(true);
        try {
            const [statusRes, listRes] = await Promise.all([
                fetch('/api/secrets/status', { credentials: 'include' }),
                fetch('/api/secrets', { credentials: 'include' })
            ]);
            if (statusRes.ok) setStatus(await statusRes.json());
            if (listRes.ok) setSecrets(await listRes.json());
        } catch {
            setSecrets([]);
        } finally {
            setLoading(false);
        }
    }, []);

    useEffect(() => { load(); }, [load]);

    const nameValid = NAME_PATTERN.test(name.trim());
    const canAdd = !!status?.keyConfigured && nameValid && value.length > 0 && !saving;

    const add = async () => {
        if (!canAdd) return;
        setSaving(true);
        try {
            const res = await fetch('/api/secrets', {
                method: 'POST',
                credentials: 'include',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ name: name.trim(), value, description: description.trim() })
            });
            if (!res.ok) {
                onNotify(await readError(res), 'error');
                return;
            }
            setName('');
            setValue('');
            setDescription('');
            onNotify('Secret saved.', 'success');
            await load();
        } finally {
            setSaving(false);
        }
    };

    const replace = async (id: string) => {
        if (!replacement) return;
        setSaving(true);
        try {
            const res = await fetch(`/api/secrets/${encodeURIComponent(id)}`, {
                method: 'PUT',
                credentials: 'include',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ value: replacement })
            });
            if (!res.ok) {
                onNotify(await readError(res), 'error');
                return;
            }
            setReplacingId(null);
            setReplacement('');
            onNotify('Secret updated.', 'success');
            await load();
        } finally {
            setSaving(false);
        }
    };

    const remove = async (secret: SecretEntry) => {
        const confirmed = await onConfirm(`Delete secret "${secret.name}"? Tasks that use {$secret.${secret.name}} will get an empty value.`);
        if (!confirmed) return;
        const res = await fetch(`/api/secrets/${encodeURIComponent(secret.id)}`, { method: 'DELETE', credentials: 'include' });
        if (!res.ok) {
            onNotify(await readError(res), 'error');
            return;
        }
        onNotify('Secret deleted.', 'success');
        await load();
    };

    return (
        <div className="glass-card p-8 rounded-[40px] space-y-6">
            <div className="flex items-center gap-4 mb-2">
                <div className="w-10 h-10 rounded-2xl bg-white/5 flex items-center justify-center text-gray-400"><MaterialIcon name="key" className="text-xl" /></div>
                <div>
                    <h3 className="text-sm font-bold text-white uppercase tracking-widest">Secrets</h3>
                    <p className="text-[10px] text-gray-500 uppercase tracking-widest mt-1">Encrypted values for tasks · use as {'{$secret.NAME}'}</p>
                </div>
            </div>

            {status && !status.keyConfigured && (
                <div className="px-4 py-3 rounded-xl bg-yellow-500/5 border border-yellow-500/10 text-yellow-400 text-[10px]" role="alert">
                    {status.keyError || 'SECRETS_KEY is not set on the server. Generate one with `openssl rand -hex 32`, set it in the environment, and restart to store secrets.'}
                </div>
            )}
            {status && status.mismatched > 0 && (
                <div className="px-4 py-3 rounded-xl bg-red-500/5 border border-red-500/10 text-red-400 text-[10px]" role="alert">
                    {status.mismatched} secret(s) were encrypted with a different SECRETS_KEY and can't be used. Restore the old key or replace their values.
                </div>
            )}

            <div className="grid grid-cols-2 gap-3">
                <input
                    type="text"
                    placeholder="Name (e.g. STREAMLINE_PASSWORD)"
                    value={name}
                    onChange={(e) => setName(e.target.value)}
                    className={inputClass}
                    aria-label="Secret name"
                    aria-invalid={name.length > 0 && !nameValid}
                    autoComplete="off"
                />
                <input
                    type="password"
                    placeholder="Value"
                    value={value}
                    onChange={(e) => setValue(e.target.value)}
                    className={inputClass}
                    aria-label="Secret value"
                    autoComplete="new-password"
                />
                <input
                    type="text"
                    placeholder="Description (optional)"
                    value={description}
                    onChange={(e) => setDescription(e.target.value)}
                    className={`${inputClass} col-span-2`}
                    aria-label="Secret description"
                />
            </div>
            {name.length > 0 && !nameValid && (
                <p className="text-[10px] text-red-400">Letters, digits and underscores only; must not start with a digit.</p>
            )}
            <button type="button" onClick={add} disabled={!canAdd} className={buttonClass}>
                {saving ? 'Saving…' : 'Add Secret'}
            </button>

            <div className="space-y-3">
                {loading && secrets.length === 0 && <p className="text-[10px] text-gray-500">Loading…</p>}
                {!loading && secrets.length === 0 && <p className="text-[10px] text-gray-500">No secrets yet.</p>}
                {secrets.map((secret) => {
                    const reference = `{$secret.${secret.name}}`;
                    return (
                        <div key={secret.id} className="p-4 rounded-2xl bg-white/[0.03] border border-white/5 space-y-3">
                            <div className="flex items-center justify-between gap-4">
                                <div className="min-w-0">
                                    <div className="text-[11px] text-white font-mono truncate">{secret.name}</div>
                                    <div className="text-[9px] text-gray-500 mt-1 truncate">
                                        {secret.description ? `${secret.description} · ` : ''}updated {new Date(secret.updatedAt).toLocaleString()}
                                    </div>
                                </div>
                                <div className="flex items-center gap-2 shrink-0">
                                    <CopyButton text={reference} />
                                    <button
                                        type="button"
                                        onClick={() => { setReplacingId(replacingId === secret.id ? null : secret.id); setReplacement(''); }}
                                        className={buttonClass}
                                        disabled={!status?.keyConfigured}
                                        aria-label={`Replace value of ${secret.name}`}
                                    >
                                        Replace
                                    </button>
                                    <button
                                        type="button"
                                        onClick={() => remove(secret)}
                                        className="px-4 py-3 bg-red-500/5 border border-red-500/10 text-red-400 rounded-xl text-[9px] font-bold uppercase tracking-widest hover:bg-red-500/10 transition-all focus:outline-none focus-visible:ring-2 focus-visible:ring-red-500/50"
                                        aria-label={`Delete ${secret.name}`}
                                    >
                                        Delete
                                    </button>
                                </div>
                            </div>
                            {replacingId === secret.id && (
                                <div className="flex gap-2">
                                    <input
                                        type="password"
                                        placeholder="New value"
                                        value={replacement}
                                        onChange={(e) => setReplacement(e.target.value)}
                                        className={`${inputClass} flex-1`}
                                        aria-label={`New value for ${secret.name}`}
                                        autoComplete="new-password"
                                        autoFocus
                                    />
                                    <button type="button" onClick={() => replace(secret.id)} disabled={!replacement || saving} className={buttonClass}>
                                        Save
                                    </button>
                                </div>
                            )}
                        </div>
                    );
                })}
            </div>
        </div>
    );
};

export default SecretsPanel;
