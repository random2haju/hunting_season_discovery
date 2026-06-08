/**
 * Episode Timeline — vertical chronological list of episode cards per device.
 * Left panel: searchable device list.  Right panel: episode cards + scene table.
 */

import React, { useEffect, useRef, useState } from 'react'
import {
  Button, Col, Collapse, Empty, Input, List, Modal, Popover, Row, Segmented, Space, Spin, Table, Tag, Tooltip, Typography,
} from 'antd'
import { CopyOutlined, HistoryOutlined, SearchOutlined, StopOutlined } from '@ant-design/icons'
import { useSearchParams } from 'react-router-dom'
import { api } from '../api'
import EmptyState from '../components/EmptyState'
import { ScoreBreakdown, SuppressModal } from '../components/EntityDetailDrawer'
import { useApp } from '../context/AppContext'
import { palette, riskColor as RISK_COLOR } from '../theme'

const { Text, Title } = Typography

// Detect and decode PowerShell -EncodedCommand / -enc base64 blobs (UTF-16LE)
const PS_ENC_RE = /-(?:EncodedCommand|enc(?:odedCommand)?)\s+([A-Za-z0-9+/]{20,}={0,2})/i

function decodePS1(b64) {
  try {
    const binary = atob(b64)
    let out = ''
    for (let i = 0; i + 1 < binary.length; i += 2) {
      out += String.fromCharCode(binary.charCodeAt(i) | (binary.charCodeAt(i + 1) << 8))
    }
    return out
  } catch {
    return null
  }
}

function EvidenceCell({ value }) {
  const [open, setOpen] = useState(false)
  if (!value) return <Text style={{ fontSize: 11 }}>—</Text>

  const match = PS_ENC_RE.exec(value)
  const decoded = match ? decodePS1(match[1]) : null

  const copyText = (text) => navigator.clipboard?.writeText(text)

  return (
    <>
      <Space size={4} style={{ flexWrap: 'nowrap', maxWidth: '100%' }}>
        <Text
          style={{ fontSize: 11, cursor: 'pointer', maxWidth: 340, display: 'inline-block' }}
          ellipsis
          onClick={() => setOpen(true)}
        >
          {value}
        </Text>
        {decoded && (
          <Tooltip title="Contains decoded PowerShell">
            <Tag color="volcano" style={{ fontSize: 10, cursor: 'pointer', flexShrink: 0 }}
              onClick={() => setOpen(true)}>PS1</Tag>
          </Tooltip>
        )}
      </Space>

      <Modal
        open={open}
        onCancel={() => setOpen(false)}
        footer={null}
        title="Evidence detail"
        width={720}
      >
        <Space direction="vertical" style={{ width: '100%' }} size={12}>
          <div>
            <Space style={{ marginBottom: 4 }}>
              <Text strong style={{ fontSize: 12 }}>Raw evidence</Text>
              <Tooltip title="Copy">
                <CopyOutlined style={{ cursor: 'pointer', color: palette.muted }}
                  onClick={() => copyText(value)} />
              </Tooltip>
            </Space>
            <div style={{
              background: palette.bg, borderRadius: 4, padding: '8px 10px',
              fontFamily: 'monospace', fontSize: 11, wordBreak: 'break-all',
              whiteSpace: 'pre-wrap', maxHeight: 200, overflowY: 'auto',
              border: `1px solid ${palette.border}`,
            }}>
              {value}
            </div>
          </div>

          {decoded && (
            <div>
              <Space style={{ marginBottom: 4 }}>
                <Text strong style={{ fontSize: 12 }}>Decoded PowerShell</Text>
                <Tooltip title="Copy">
                  <CopyOutlined style={{ cursor: 'pointer', color: palette.muted }}
                    onClick={() => copyText(decoded)} />
                </Tooltip>
              </Space>
              <div style={{
                background: palette.bg, borderRadius: 4, padding: '8px 10px',
                fontFamily: 'monospace', fontSize: 11, wordBreak: 'break-all',
                whiteSpace: 'pre-wrap', maxHeight: 300, overflowY: 'auto',
                border: `1px solid ${palette.border}`, color: palette.success,
              }}>
                {decoded}
              </div>
            </div>
          )}
        </Space>
      </Modal>
    </>
  )
}

function ScoreCell({ record }) {
  const final = record.ScoreContribution
  const base  = record.BaseScore
  if (final == null) return <Text style={{ fontSize: 11 }}>—</Text>

  const hasBreakdown = base != null
  const rows = hasBreakdown ? [
    { label: 'Base',        val: base,                             always: true },
    { label: 'Context',     val: record.ContextMultiplier,         always: false },
    { label: 'Workflow',    val: record.WorkflowMultiplier,        always: false },
    { label: 'Prevalence',  val: record.PrevalenceMultiplier,      always: false },
  ] : []

  const content = hasBreakdown ? (
    <div style={{ fontFamily: 'monospace', fontSize: 11, lineHeight: '1.8' }}>
      {rows.filter(r => r.always || (r.val != null && r.val !== 1)).map(r => (
        <div key={r.label} style={{ display: 'flex', justifyContent: 'space-between', gap: 16 }}>
          <span style={{ color: palette.muted }}>{r.label}</span>
          <span style={{ color: r.val < 1 ? palette.secondary : r.val > 1 ? palette.success : palette.muted }}>
            {r.val?.toFixed(3) ?? '—'}
          </span>
        </div>
      ))}
      <div style={{ borderTop: `1px solid ${palette.border}`, marginTop: 4, paddingTop: 4,
                    display: 'flex', justifyContent: 'space-between', gap: 16 }}>
        <span style={{ color: palette.muted }}>Final</span>
        <span style={{ color: palette.text, fontWeight: 600 }}>{final.toFixed(3)}</span>
      </div>
    </div>
  ) : null

  return hasBreakdown ? (
    <Tooltip title={content} color="#1a1a1a" overlayInnerStyle={{ minWidth: 180 }}>
      <Text style={{ fontSize: 11, cursor: 'default',
                     color: final < (base ?? final) ? '#fa8c16' : undefined }}>
        {final.toFixed(2)}
      </Text>
    </Tooltip>
  ) : (
    <Text style={{ fontSize: 11 }}>{final.toFixed(2)}</Text>
  )
}

// Prevalence badge derived from EnvDeviceCount
function PrevalenceBadge({ count }) {
  if (count == null) return null
  if (count >= 10) {
    return (
      <Tooltip title={`Seen on ${count} devices — widespread, likely noisy`}>
        <Tag color="default" style={{ fontSize: 10, margin: 0 }}>×{count} widespread</Tag>
      </Tooltip>
    )
  }
  if (count <= 2) {
    return (
      <Tooltip title={`Seen on only ${count} device${count === 1 ? '' : 's'} — rare signal`}>
        <Tag color="green" style={{ fontSize: 10, margin: 0 }}>×{count} rare</Tag>
      </Tooltip>
    )
  }
  return (
    <Tooltip title={`Seen on ${count} devices`}>
      <Tag style={{ fontSize: 10, margin: 0 }}>×{count}</Tag>
    </Tooltip>
  )
}

const WORKFLOW_COLORS = {
  AIWorkflow:           'purple',
  DeveloperAutomation:  'blue',
  Operational:          'default',
}

function makeSceneCols(mode) {
  const crossCol = mode === 'Device'
    ? {
        title: 'Account',
        dataIndex: 'AccountName',
        key: 'AccountName',
        width: 120,
        ellipsis: true,
        render: (v) => v ? <Text code style={{ fontSize: 11 }}>{v}</Text> : <Text type="secondary">—</Text>,
      }
    : {
        title: 'Device',
        dataIndex: 'DeviceName',
        key: 'DeviceName',
        width: 140,
        ellipsis: true,
        render: (v) => v ? <Text code style={{ fontSize: 11 }}>{v}</Text> : <Text type="secondary">—</Text>,
      }

  return [
    {
      title: 'Timestamp', dataIndex: 'Timestamp', key: 'Timestamp', width: 150,
      render: (v) => v ? v.replace('T', ' ') : '—',
    },
    crossCol,
    {
      title: 'Detection', dataIndex: 'DetectionType', key: 'DetectionType', ellipsis: true,
    },
    {
      title: 'Family', dataIndex: 'BehaviorFamily', key: 'BehaviorFamily', width: 130,
      render: (v) => v && v !== 'Unknown'
        ? <Tag color="geekblue" style={{ fontSize: 10, margin: 0 }}>{v}</Tag>
        : null,
    },
    {
      title: 'Workflow', dataIndex: 'WorkflowClass', key: 'WorkflowClass', width: 100,
      render: (v) => v
        ? <Tag color={WORKFLOW_COLORS[v] ?? 'default'} style={{ fontSize: 10, margin: 0 }}>{v}</Tag>
        : null,
    },
    {
      title: 'Tactic', dataIndex: 'TacticCategory', key: 'TacticCategory', width: 120,
    },
    {
      title: 'Score', key: 'ScoreContribution', width: 70,
      render: (_, record) => <ScoreCell record={record} />,
    },
    {
      title: 'Prevalence', dataIndex: 'EnvDeviceCount', key: 'EnvDeviceCount', width: 110,
      render: (v) => <PrevalenceBadge count={v} />,
    },
    {
      title: 'Evidence', dataIndex: 'Evidence', key: 'Evidence',
      render: (v) => <EvidenceCell value={v} />,
    },
  ]
}

function EpisodeCard({ ep, scenes, mode }) {
  const tactics = ep.Tactics?.split(', ').filter(Boolean) ?? []
  const families = ep.BehaviorFamilies?.split(', ').filter(Boolean) ?? []

  const epScenes = scenes.filter((s) => {
    if (!ep.StartTime || !ep.EndTime) return false
    const ts = s.Timestamp
    return ts >= ep.StartTime && ts <= ep.EndTime
  })

  // Distinct cross-reference identities in this episode
  const crossKey = mode === 'Device' ? 'AccountName' : 'DeviceName'
  const crossLabel = mode === 'Device' ? 'Users' : 'Devices'
  const crossIds = [...new Set(epScenes.map((s) => s[crossKey]).filter(Boolean))].sort()

  const sceneCols = makeSceneCols(mode)

  return (
    <Collapse
      size="small"
      style={{ marginBottom: 8 }}
      items={[
        {
          key: '1',
          label: (
            <Space wrap>
              <Popover
                content={<ScoreBreakdown ep={ep} />}
                title="Score breakdown"
                trigger="hover"
                mouseEnterDelay={0.3}
                placement="rightTop"
              >
                <Text
                  strong
                  onClick={(e) => e.stopPropagation()}
                  style={{
                    color: RISK_COLOR(ep.EpisodeRiskScore ?? 0),
                    cursor: 'help',
                    borderBottom: `1px dotted ${palette.muted}`,
                  }}
                >
                  {ep.EpisodeRiskScore?.toFixed(1) ?? '—'}
                </Text>
              </Popover>
              <Text type="secondary" style={{ fontSize: 11 }}>
                {ep.StartTime?.replace('T', ' ')} — {ep.DurationHours?.toFixed(1)}h
              </Text>
              <Text style={{ fontSize: 11 }}>{ep.SceneCount} scene{ep.SceneCount !== 1 ? 's' : ''}</Text>
              {tactics.map((t) => <Tag key={t} style={{ fontSize: 10 }}>{t}</Tag>)}
              {ep.AdaptiveBehaviorFlag && <Tag color="volcano">Adaptive</Tag>}
              {ep.TacticTransitions && <Tag color="purple">Transition</Tag>}
              {crossIds.length > 0 && (
                <Text type="secondary" style={{ fontSize: 11 }}>
                  {crossLabel}:{' '}
                  {crossIds.map((id) => (
                    <Tag key={id} style={{ fontSize: 10, margin: '0 2px' }}>{id}</Tag>
                  ))}
                </Text>
              )}
            </Space>
          ),
          children: (
            <Space direction="vertical" style={{ width: '100%' }} size={8}>
              {families.length > 0 && (
                <Space size={4}>
                  <Text type="secondary" style={{ fontSize: 11 }}>Families:</Text>
                  {families.map((f) => <Tag key={f} color="blue" style={{ fontSize: 10 }}>{f}</Tag>)}
                </Space>
              )}
              {ep.AdaptiveBehaviorReason && (
                <Text type="secondary" style={{ fontSize: 11 }}>
                  ⚡ {ep.AdaptiveBehaviorReason}
                </Text>
              )}
              <Table
                dataSource={epScenes.length ? epScenes : scenes.slice(0, 0)}
                columns={sceneCols}
                rowKey={(r, i) => i}
                size="small"
                pagination={false}
                scroll={{ x: 900 }}
                locale={{ emptyText: 'No scenes matched this time window' }}
              />
            </Space>
          ),
        },
      ]}
    />
  )
}

export default function EpisodesPage() {
  const [searchParams] = useSearchParams()
  const urlEntity = searchParams.get('entity')
  const urlType   = searchParams.get('type')
  const urlMode   = urlType === 'User' ? 'User' : 'Device'

  const [mode, setMode] = useState(() => urlEntity ? urlMode : 'Device')
  const [allEntities, setAllEntities] = useState([])
  const [entitySearch, setEntitySearch] = useState('')
  const [selected, setSelected] = useState(null)
  const [detail, setDetail] = useState(null)
  const [loadingList, setLoadingList] = useState(true)
  const [loadingDetail, setLoadingDetail] = useState(false)
  const [suppressOpen, setSuppressOpen] = useState(false)
  const { pipelineStatus, selectedEntity, setSelectedEntity, navigateTo } = useApp()
  // Holds a pending navigation target across the mode-change → list-reload cycle.
  // Pre-seeded from URL params so new-tab opens land on the right entity.
  const pendingNav = useRef(urlEntity ? { name: urlEntity, mode: urlMode } : null)
  // Remembers the entity that was successfully selected via URL params or cross-module nav
  // so that subsequent pipelineStatus-triggered list reloads don't clear the selection.
  const confirmedNav = useRef(null)

  // Load entity list when mode or data changes.
  // pendingNav.current carries { name, mode } for cross-module jumps. We only
  // consume it when the fetch that completes matches the target mode — the
  // Device-mode fetch that was already in flight when navigation fired must not
  // consume the User-mode pending target.
  useEffect(() => {
    setLoadingList(true)
    const fetchMode = mode
    const req = fetchMode === 'Device' ? api.allEpisodes() : api.allUserEpisodes()
    req.then(({ data: d }) => {
      const key = fetchMode === 'Device' ? 'DeviceName' : 'AccountName'
      const entities = [...new Set((d?.data ?? []).map((r) => r[key]).filter(Boolean))].sort()
      setAllEntities(entities)
      setLoadingList(false)
      const nav = pendingNav.current
      if (nav && nav.mode === fetchMode) {
        pendingNav.current = null
        confirmedNav.current = { name: nav.name, mode: fetchMode }
        setSelected(nav.name)
      } else if (!nav) {
        // If a previously confirmed entity is still valid in the new list, keep it
        const confirmed = confirmedNav.current
        if (confirmed && confirmed.mode === fetchMode && entities.includes(confirmed.name)) {
          // selection is still valid — don't clear
        } else {
          confirmedNav.current = null
          setSelected(null)
          setDetail(null)
        }
      }
      // nav exists but targets a different mode — leave it for that mode's fetch
    })
  }, [pipelineStatus.loaded_file, mode])

  // Cross-module navigation — stash { name, mode } before changing mode so the
  // correct fetch above can pick it up once its entity list is ready.
  // Also clear confirmedNav so the new target takes over as the stable selection.
  useEffect(() => {
    if (!selectedEntity) return
    const targetMode = selectedEntity.type === 'User' ? 'User' : 'Device'
    confirmedNav.current = null
    pendingNav.current = { name: selectedEntity.name, mode: targetMode }
    setMode(targetMode)
    setSelectedEntity(null)
  }, [selectedEntity, setSelectedEntity])

  useEffect(() => {
    if (!selected) return
    setLoadingDetail(true)
    const req = mode === 'Device' ? api.deviceEpisodes(selected) : api.userEpisodes(selected)
    req.then(({ data: d }) => {
      setDetail(d)
      setLoadingDetail(false)
    })
  }, [selected, mode])

  if (!loadingList && !pipelineStatus.is_loaded) return <EmptyState />

  const filtered = entitySearch
    ? allEntities.filter((e) => e.toLowerCase().includes(entitySearch.toLowerCase()))
    : allEntities

  const placeholder = mode === 'Device' ? 'Select a device to view its episodes'
                                        : 'Select a user to view their episodes'

  return (
    <Row gutter={16} style={{ height: 'calc(100vh - 120px)' }}>
      {/* Entity list */}
      <Col flex="220px" style={{ height: '100%', overflowY: 'auto' }}>
        <Segmented
          options={['Device', 'User']}
          value={mode}
          onChange={(v) => setMode(v)}
          size="small"
          style={{ marginBottom: 8, width: '100%' }}
        />
        <Input
          prefix={<SearchOutlined />}
          placeholder={`Filter ${mode.toLowerCase()}s…`}
          value={entitySearch}
          onChange={(e) => setEntitySearch(e.target.value)}
          allowClear
          size="small"
          style={{ marginBottom: 8 }}
        />
        {loadingList ? (
          <Spin size="small" />
        ) : (
          <List
            size="small"
            dataSource={filtered}
            renderItem={(e) => (
              <List.Item
                style={{
                  cursor: 'pointer',
                  padding: '6px 8px',
                  background: e === selected ? 'rgba(25, 200, 255, 0.15)' : 'transparent',
                  borderRadius: 4,
                }}
                onClick={() => setSelected(e)}
              >
                <Text code style={{ fontSize: 11 }}>{e}</Text>
              </List.Item>
            )}
          />
        )}
      </Col>

      {/* Episode timeline */}
      <Col flex="1" style={{ height: '100%', overflowY: 'auto' }}>
        {!selected ? (
          <Empty description={placeholder} />
        ) : loadingDetail ? (
          <Spin />
        ) : !detail || detail.episodes.length === 0 ? (
          <Empty description={`No episodes found for ${selected}`} />
        ) : (
          <>
            <SuppressModal
              open={suppressOpen}
              name={selected ?? ''}
              type={mode}
              onClose={() => setSuppressOpen(false)}
            />
            <Space wrap style={{ marginBottom: 12 }} align="center">
              <Title level={5} style={{ marginBottom: 0 }}>
                {selected} — {detail.episodes.length} episode{detail.episodes.length !== 1 ? 's' : ''}
              </Title>
              <Button
                size="small"
                icon={<HistoryOutlined />}
                onClick={() => navigateTo(selected, mode, '/history')}
              >
                History
              </Button>
              <Button
                size="small"
                danger
                icon={<StopOutlined />}
                onClick={() => setSuppressOpen(true)}
              >
                Suppress
              </Button>
            </Space>
            {detail.episodes.map((ep, i) => (
              <EpisodeCard key={i} ep={ep} scenes={detail.scenes ?? []} mode={mode} />
            ))}
          </>
        )}
      </Col>
    </Row>
  )
}
