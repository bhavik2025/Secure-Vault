import { useState } from 'react'
import { useResource } from '../hooks/useResource'
import { api } from '../lib/api'
import { errorMessage } from '../lib/errors'
import { formatDateTime } from '../lib/format'
import type { Access, Share, ShareTreeNode } from '../lib/types'
import { ShareDialog } from './ShareDialog'
import { useToast } from './Toast'
import { Badge, Button, Card, ConfirmDialog, EmptyState, ErrorBanner, LoadingBlock, Table, Td, Th, statusTone } from './ui'

function permissionBadges(s: { can_view: boolean; can_edit: boolean; can_share: boolean; is_view_once: boolean }) {
  return (
    <span className="flex flex-wrap gap-1">
      {s.can_view && <Badge tone="info">View</Badge>}
      {s.can_edit && <Badge tone="warn">Edit</Badge>}
      {s.can_share && <Badge tone="neutral">Share</Badge>}
      {s.is_view_once && <Badge tone="warn">One-time</Badge>}
    </span>
  )
}

function TreeNode({ node, depth = 0 }: { node: ShareTreeNode; depth?: number }) {
  return (
    <li>
      <div className="flex flex-wrap items-center gap-2 py-1 text-sm" style={{ paddingLeft: depth * 20 }}>
        <span aria-hidden>{depth ? '↳' : '●'}</span>
        <span className="font-medium">{node.grantee}</span>
        <span className="text-slate-500">from {node.grantor}</span>
        {permissionBadges({ can_view: node.view, can_edit: node.edit, can_share: node.share, is_view_once: node.view_once })}
        <Badge tone={statusTone(node.status)}>{node.status}</Badge>
        {node.expires_at && <span className="text-xs text-slate-500">until {formatDateTime(node.expires_at)}</span>}
      </div>
      {node.children.length > 0 && (
        <ul>
          {node.children.map((c) => (
            <TreeNode key={c.id} node={c} depth={depth + 1} />
          ))}
        </ul>
      )}
    </li>
  )
}

export function SharesPanel({ credentialId, access }: { credentialId: number; access: Access }) {
  const { notify } = useToast()
  const owner = access.role === 'owner'
  const shares = useResource(
    () => api.get<{ results: Share[] }>(`/vault/credentials/${credentialId}/shares/`),
    [credentialId],
  )
  const tree = useResource(
    () => (owner ? api.get<{ tree: ShareTreeNode[] }>(`/vault/credentials/${credentialId}/shares/tree/`) : Promise.resolve(null)),
    [credentialId, owner],
  )
  const [sharing, setSharing] = useState(false)
  const [revoking, setRevoking] = useState<Share | null>(null)
  const [busy, setBusy] = useState(false)
  const [showTree, setShowTree] = useState(false)

  function reload() {
    shares.reload()
    tree.reload()
  }

  async function revoke() {
    if (!revoking) return
    setBusy(true)
    try {
      const r = await api.post<Share>(`/vault/shares/${revoking.id}/revoke/`)
      notify(
        r.grants_revoked && r.grants_revoked > 1
          ? `Access revoked for ${r.grants_revoked} people (including everyone it was passed on to).`
          : 'Access revoked.',
      )
      setRevoking(null)
      reload()
    } catch (e) {
      notify(errorMessage(e), 'error')
    } finally {
      setBusy(false)
    }
  }

  const rows = shares.data?.results ?? []
  return (
    <Card
      title={owner ? 'Sharing' : 'Access you have delegated'}
      actions={
        <div className="flex gap-2">
          {owner && (
            <Button variant="secondary" onClick={() => setShowTree((s) => !s)} aria-pressed={showTree}>
              {showTree ? 'Show list' : 'Delegation tree'}
            </Button>
          )}
          <Button onClick={() => setSharing(true)}>{owner ? 'Share' : 'Delegate'}</Button>
        </div>
      }
    >
      <ErrorBanner error={shares.error} onRetry={shares.reload} />
      {shares.loading && <LoadingBlock />}
      {!shares.loading && !shares.error && showTree && owner ? (
        tree.data && tree.data.tree.length ? (
          <ul aria-label="Delegation tree">
            {tree.data.tree.map((n) => (
              <TreeNode key={n.id} node={n} />
            ))}
          </ul>
        ) : (
          <EmptyState title="Nothing shared yet" />
        )
      ) : (
        !shares.loading &&
        !shares.error &&
        (rows.length === 0 ? (
          <EmptyState title="Nothing shared yet">Share this credential with a colleague, with an expiry if you like.</EmptyState>
        ) : (
          <Table caption="Shares of this credential">
            <thead>
              <tr>
                <Th>Person</Th>
                <Th>Permissions</Th>
                <Th>Expires</Th>
                <Th>Status</Th>
                <Th />
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-100 dark:divide-slate-800">
              {rows.map((s) => (
                <tr key={s.id}>
                  <Td>
                    {s.grantee.email}
                    {s.depth > 1 && <span className="ml-2 text-xs text-slate-500">via {s.grantor.email}</span>}
                  </Td>
                  <Td>{permissionBadges(s)}</Td>
                  <Td>{s.expires_at ? formatDateTime(s.expires_at) : 'Never'}</Td>
                  <Td>
                    <Badge tone={statusTone(s.status)}>{s.status}</Badge>
                  </Td>
                  <Td>
                    {s.status === 'ACTIVE' && (
                      <Button variant="ghost" onClick={() => setRevoking(s)} aria-label={`Revoke access for ${s.grantee.email}`}>
                        Revoke
                      </Button>
                    )}
                  </Td>
                </tr>
              ))}
            </tbody>
          </Table>
        ))
      )}

      <ShareDialog open={sharing} onClose={() => setSharing(false)} credentialId={credentialId} access={access} onShared={reload} />
      <ConfirmDialog
        open={!!revoking}
        danger
        busy={busy}
        title="Revoke access?"
        confirmLabel="Revoke"
        message={
          <>
            <p>
              <strong>{revoking?.grantee.email}</strong> will lose access immediately.
            </p>
            <p className="mt-2">Anyone they passed this access on to will lose it too.</p>
          </>
        }
        onConfirm={() => void revoke()}
        onCancel={() => setRevoking(null)}
      />
    </Card>
  )
}
