/**
 * Episode Timeline — vertical chronological list of episode cards per device.
 * Left panel: searchable device list.  Right panel: episode cards + scene table.
 */

import React, { useEffect, useRef, useState } from 'react'
import {
  Col, Collapse, Empty, Input, List, Modal, Row, Segmented, Space, Spin, Table, Tag, Tooltip, Typography,
} from 'antd'
import { CopyOutlined, SearchOutlined } from '@ant-design/icons'
import { api } from '../api'
import EmptyState from '../components/EmptyState'
import { useApp } from '../context/AppContext'

const { Text, Title } = Typography

const RISK_COLOR = (v) =>
  v >= 50 ? '#ff4d4f' : v >= 20 ? '#fa8c16' : v >= 5 ? '#faad14' : '#52c41a'

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
                <CopyOutlined style={{ cursor: 'pointer', color: '#888' }}
                  onClick={() => copyText(value)} />
              </Tooltip>
            </Space>
            <div style={{
              background: '#141414', borderRadius: 4, padding: '8px 10px',
              fontFamily: 'monospace', fontSize: 11, wordBreak: 'break-all',
              whiteSpace: 'pre-wrap', maxHeight: 200, overflowY: 'auto',
              border: '1px solid #303030',
            }}>
              {value}
            </div>
          </div>

          {decoded && (
            <div>
              <Space style={{ marginBottom: 4 }}>
                <Text strong style={{ fontSize: 12 }}>Decoded PowerShell</Text>
                <Tooltip title="Copy">
                  <CopyOutlined style={{ cursor: 'pointer', color: '#888' }}
                    onClick={() => copyText(decoded)} />
                </Tooltip>
              </Space>
              <div style={{
                background: '#0d1117', borderRadius: 4, padding: '8px 10px',
                fontFamily: 'monospace', fontSize: 11, wordBreak: 'break-all',
                whiteSpace: 'pre-wrap', maxHeight: 300, overflowY: 'auto',
                border: '1px solid #1a3a2a', color: '#7ee787',
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
          <span style={{ color: '#888' }}>{r.label}</span>
          <span style={{ color: r.val < 1 ? '#fa8c16' : r.val > 1 ? '#52c41a' : '#aaa' }}>
            {r.val?.toFixed(3) ?? '—'}
          </span>
        </div>
      ))}
      <div style={{ borderTop: '1px solid #303030', marginTop: 4, paddingTop: 4,
                    display: 'flex', justifyContent: 'space-between', gap: 16 }}>
        <span style={{ color: '#888' }}>Final</span>
        <span style={{ color: '#fff', fontWeight: 600 }}>{final.toFixed(3)}</span>
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

const SCENE_COLS = [
  { title: 'Timestamp', dataIndex: 'Timestamp', key: 'Timestamp', width: 160,
    render: (v) => v ? v.replace('T', ' ') : '—' },
  { title: 'Detection', dataIndex: 'DetectionType', key: 'DetectionType', ellipsis: true },
  { title: 'Tactic', dataIndex: 'TacticCategory', key: 'TacticCategory', width: 130 },
  { title: 'Score', key: 'ScoreContribution', width: 70,
    render: (_, record) => <ScoreCell record={record} /> },
  { title: 'Evidence', dataIndex: 'Evidence', key: 'Evidence',
    render: (v) => <EvidenceCell value={v} /> },
]

function EpisodeCard({ ep, scenes }) {
  const tactics = ep.Tactics?.split(', ').filter(Boolean) ?? []
  const families = ep.BehaviorFamilies?.split(', ').filter(Boolean) ?? []

  const epScenes = scenes.filter((s) => {
    if (!ep.StartTime || !ep.EndTime) return false
    const ts = s.Timestamp
    return ts >= ep.StartTime && ts <= ep.EndTime
  })

  return (
    <Collapse
      size="small"
      style={{ marginBottom: 8 }}
      items={[
        {
          key: '1',
          label: (
            <Space wrap>
              <Text strong style={{ color: RISK_COLOR(ep.EpisodeRiskScore ?? 0) }}>
                {ep.EpisodeRiskScore?.toFixed(1) ?? '—'}
              </Text>
              <Text type="secondary" style={{ fontSize: 11 }}>
                {ep.StartTime?.replace('T', ' ')} — {ep.DurationHours?.toFixed(1)}h
              </Text>
              <Text style={{ fontSize: 11 }}>{ep.SceneCount} scene{ep.SceneCount !== 1 ? 's' : ''}</Text>
              {tactics.map((t) => <Tag key={t} style={{ fontSize: 10 }}>{t}</Tag>)}
              {ep.AdaptiveBehaviorFlag && <Tag color="volcano">Adaptive</Tag>}
              {ep.TacticTransitions && <Tag color="purple">Transition</Tag>}
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
                columns={SCENE_COLS}
                rowKey={(r, i) => i}
                size="small"
                pagination={false}
                scroll={{ x: 700 }}
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
  const [mode, setMode] = useState('Device')
  const [allEntities, setAllEntities] = useState([])
  const [entitySearch, setEntitySearch] = useState('')
  const [selected, setSelected] = useState(null)
  const [detail, setDetail] = useState(null)
  const [loadingList, setLoadingList] = useState(true)
  const [loadingDetail, setLoadingDetail] = useState(false)
  const { pipelineStatus, selectedEntity, setSelectedEntity } = useApp()
  // Holds a pending navigation target across the mode-change → list-reload cycle
  const pendingNav = useRef(null)

  // Load entity list when mode or data changes.
  // If a navigation target is pending (cross-module jump), apply it after load
  // instead of resetting selection — otherwise the mode-change effect would
  // overwrite the selection set by navigation.
  useEffect(() => {
    setLoadingList(true)
    const req = mode === 'Device' ? api.allEpisodes() : api.allUserEpisodes()
    req.then(({ data: d }) => {
      const key = mode === 'Device' ? 'DeviceName' : 'AccountName'
      const entities = [...new Set((d?.data ?? []).map((r) => r[key]).filter(Boolean))].sort()
      setAllEntities(entities)
      setLoadingList(false)
      if (pendingNav.current) {
        setSelected(pendingNav.current)
        pendingNav.current = null
      } else {
        setSelected(null)
        setDetail(null)
      }
    })
  }, [pipelineStatus.loaded_file, mode])

  // Cross-module navigation — store target in ref before changing mode so the
  // list-reload effect above can pick it up after the entity list is ready.
  useEffect(() => {
    if (!selectedEntity) return
    const targetMode = selectedEntity.type === 'User' ? 'User' : 'Device'
    pendingNav.current = selectedEntity.name
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
                  background: e === selected ? '#1677ff22' : 'transparent',
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
            <Title level={5} style={{ marginBottom: 12 }}>
              {selected} — {detail.episodes.length} episode{detail.episodes.length !== 1 ? 's' : ''}
            </Title>
            {detail.episodes.map((ep, i) => (
              <EpisodeCard key={i} ep={ep} scenes={detail.scenes ?? []} />
            ))}
          </>
        )}
      </Col>
    </Row>
  )
}
