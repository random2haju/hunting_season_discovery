/**
 * EntityDetailDrawer — slide-out triage panel.
 *
 * Usage:
 *   const { openDetail, entityDetailDrawer } = useEntityDetailDrawer()
 *
 *   <Table
 *     onRow={(r) => ({ onClick: () => openDetail(r), onContextMenu: ... })}
 *   />
 *   {entityDetailDrawer}
 */

import React, { useCallback, useEffect, useState } from 'react'
import {
  Button, Col, DatePicker, Drawer, Form, Input,
  Modal, Row, Space, Spin, Statistic, Tag, Tooltip, Typography, message,
} from 'antd'
import {
  EyeOutlined, HistoryOutlined, StopOutlined,
} from '@ant-design/icons'
import { api } from '../api'
import { useApp } from '../context/AppContext'
import { palette, riskColor as RISK_COLOR } from '../theme'

const { Text } = Typography

const FLAG_COLORS = {
  IsScoreSpike:      'red',
  IsNewHigh:         'orange',
  IsTacticExpansion: 'purple',
  IsAdaptingTactics: 'magenta',
  IsEmergingEntity:  'cyan',
}
const FLAG_LABELS = {
  IsScoreSpike:      'Spike',
  IsNewHigh:         'NewHigh',
  IsTacticExpansion: 'TacticExp',
  IsAdaptingTactics: 'Adapting',
  IsEmergingEntity:  'Emerging',
}

export function resolveEntity(record) {
  if (!record) return { name: '', type: 'Device' }
  const name = record.EntityName ?? record.DeviceName ?? record.AccountName ?? ''
  const type =
    record.EntityType ??
    (record.AccountName && !record.DeviceName ? 'User' : 'Device')
  return { name, type }
}

// ── SVG sparkline ────────────────────────────────────────────────────────────

function Sparkline({ history }) {
  if (!history?.length)
    return <Text type="secondary" style={{ fontSize: 11 }}>No history yet</Text>

  const scores = history.map((r) => r.SeasonScore ?? 0)
  const min = Math.min(...scores)
  const max = Math.max(...scores)
  const range = max - min || 1
  const W = 340, H = 54, PAD = 6

  const pts = scores.map((s, i) => ({
    x: PAD + (i / Math.max(scores.length - 1, 1)) * (W - PAD * 2),
    y: H - PAD - ((s - min) / range) * (H - PAD * 2),
    s,
    date: history[i].RunDate ?? history[i].run_date ?? null,
  }))

  const polyPts = pts.map((p) => `${p.x},${p.y}`).join(' ')
  const last = pts[pts.length - 1]

  return (
    <div>
      <svg width={W} height={H} style={{ display: 'block' }}>
        <polyline
          points={polyPts}
          fill="none"
          stroke={palette.primary}
          strokeWidth={2}
          strokeLinejoin="round"
          strokeLinecap="round"
        />
        {pts.map((p, i) => {
          const isLast = i === pts.length - 1
          const label = p.date ? `${p.date}: ${p.s.toFixed(1)}` : p.s.toFixed(1)
          return (
            <circle
              key={i}
              cx={p.x} cy={p.y}
              r={isLast ? 4 : 2.5}
              fill={isLast ? RISK_COLOR(p.s) : palette.primary}
              opacity={isLast ? 1 : 0.65}
              style={{ cursor: 'default' }}
            >
              <title>{label}</title>
            </circle>
          )
        })}
      </svg>
      <div style={{
        display: 'flex', justifyContent: 'space-between',
        fontSize: 10, color: palette.muted, marginTop: 2,
        paddingLeft: PAD, paddingRight: PAD,
      }}>
        <span>min {min.toFixed(1)}</span>
        <span>max {max.toFixed(1)}</span>
        <span style={{ color: RISK_COLOR(last.s) }}>now {last.s.toFixed(1)}</span>
      </div>
    </div>
  )
}

// ── Compact episode list ──────────────────────────────────────────────────────

function EpisodeList({ episodes }) {
  if (!episodes?.length)
    return <Text type="secondary" style={{ fontSize: 12 }}>No episodes found</Text>

  return (
    <Space direction="vertical" style={{ width: '100%' }} size={6}>
      {episodes.map((ep, i) => {
        const tactics = ep.Tactics?.split(', ').filter(Boolean) ?? []
        return (
          <div
            key={i}
            style={{
              background: palette.surface,
              borderRadius: 6,
              padding: '8px 10px',
              border: `1px solid ${palette.border}`,
            }}
          >
            <Space wrap size={6}>
              <Text strong style={{ color: RISK_COLOR(ep.EpisodeRiskScore ?? 0), minWidth: 34 }}>
                {ep.EpisodeRiskScore?.toFixed(1) ?? '—'}
              </Text>
              <Text type="secondary" style={{ fontSize: 11 }}>
                {ep.StartTime?.slice(0, 16).replace('T', ' ')}
              </Text>
              <Text style={{ fontSize: 11 }}>
                {ep.DurationHours?.toFixed(1)}h &middot; {ep.SceneCount}{' '}
                scene{ep.SceneCount !== 1 ? 's' : ''}
              </Text>
              {tactics.map((t) => (
                <Tag key={t} style={{ fontSize: 10, margin: 0 }}>{t}</Tag>
              ))}
              {ep.AdaptiveBehaviorFlag && (
                <Tag color="volcano" style={{ fontSize: 10, margin: 0 }}>Adaptive</Tag>
              )}
              {ep.TacticTransitions && (
                <Tag color="purple" style={{ fontSize: 10, margin: 0 }}>Transition</Tag>
              )}
            </Space>
          </div>
        )
      })}
    </Space>
  )
}

// ── Suppress modal (exported so other pages can reuse it) ────────────────────

export function SuppressModal({ open, name, type, onClose }) {
  const [form] = Form.useForm()

  async function handleFinish(values) {
    const body = {
      entity_type: type,
      entity_name: name,
      reason: values.reason,
      expires: values.expires ? values.expires.format('YYYY-MM-DD') : null,
    }
    const { error } = await api.addSuppression(body)
    if (error) {
      message.error(error)
    } else {
      message.success(`Suppressed ${type} "${name}"`)
      form.resetFields()
      onClose()
    }
  }

  return (
    <Modal
      title={`Suppress ${type}: ${name}`}
      open={open}
      onCancel={() => { form.resetFields(); onClose() }}
      onOk={() => form.submit()}
      okText="Suppress"
      okButtonProps={{ danger: true }}
      destroyOnClose={false}
    >
      <Form form={form} layout="vertical" onFinish={handleFinish}>
        <Form.Item
          name="reason"
          label="Reason"
          rules={[{ required: true, message: 'Please enter a reason' }]}
        >
          <Input placeholder="e.g. Known AI developer workstation" autoFocus />
        </Form.Item>
        <Form.Item name="expires" label="Expires (optional — leave blank for permanent)">
          <DatePicker style={{ width: '100%' }} format="YYYY-MM-DD" />
        </Form.Item>
      </Form>
    </Modal>
  )
}

// ── Main drawer content ───────────────────────────────────────────────────────

function DrawerContent({ record }) {
  const { navigateTo } = useApp()
  const { name, type } = resolveEntity(record)
  const [episodes, setEpisodes] = useState([])
  const [history, setHistory] = useState([])
  const [loading, setLoading] = useState(true)
  const [suppressOpen, setSuppressOpen] = useState(false)

  useEffect(() => {
    if (!name) return
    setLoading(true)
    Promise.all([
      type === 'User' ? api.userEpisodes(name) : api.deviceEpisodes(name),
      api.entityHistory(type, name),
    ]).then(([epRes, histRes]) => {
      setEpisodes(epRes.data?.episodes ?? [])
      setHistory(histRes.data?.data ?? [])
      setLoading(false)
    })
  }, [name, type])

  const flags = Object.keys(FLAG_COLORS).filter((f) => record?.[f])
  const risk = record?.TotalRisk

  return (
    <>
      <SuppressModal
        open={suppressOpen}
        name={name}
        type={type}
        onClose={() => setSuppressOpen(false)}
      />

      <Space direction="vertical" style={{ width: '100%' }} size={20}>

        {/* Anomaly flags */}
        {flags.length > 0 && (
          <Space size={4} wrap>
            {flags.map((f) => (
              <Tag key={f} color={FLAG_COLORS[f]}>{FLAG_LABELS[f]}</Tag>
            ))}
          </Space>
        )}

        {/* Key stats */}
        <Row gutter={16}>
          <Col span={6}>
            <Statistic
              title="Risk"
              value={risk?.toFixed(1) ?? '—'}
              valueStyle={{ color: RISK_COLOR(risk ?? 0), fontSize: 22 }}
            />
          </Col>
          <Col span={6}>
            <Statistic
              title="Episodes"
              value={record?.EpisodeCount ?? '—'}
              valueStyle={{ fontSize: 22 }}
            />
          </Col>
          <Col span={6}>
            <Statistic
              title="Tactics"
              value={record?.UniqueTactics ?? '—'}
              valueStyle={{ fontSize: 22 }}
            />
          </Col>
          <Col span={6}>
            <Statistic
              title="Z-Score"
              value={record?.ZScore != null ? record.ZScore.toFixed(2) : '—'}
              valueStyle={{ fontSize: 22 }}
            />
          </Col>
        </Row>

        {/* Secondary metadata */}
        <Space size={8} wrap>
          {record?.PrimaryWorkflowClass && (
            <Tag color="blue">{record.PrimaryWorkflowClass}</Tag>
          )}
          {record?.AIWorkflowScenePct != null && (
            <Text style={{ fontSize: 11 }}>AI scenes: {record.AIWorkflowScenePct}%</Text>
          )}
          {record?.RiskPercentile != null && (
            <Text style={{ fontSize: 11 }}>Percentile: {record.RiskPercentile}%</Text>
          )}
          {record?.IsSuppressed && (
            <Tooltip title={record.SuppressReason}>
              <Tag color="red">Suppressed</Tag>
            </Tooltip>
          )}
        </Space>

        {record?.TacticSet && (
          <Text type="secondary" style={{ fontSize: 11 }}>
            {record.TacticSet}
          </Text>
        )}

        {/* Score history sparkline */}
        <div>
          <Text strong style={{ fontSize: 12, display: 'block', marginBottom: 6 }}>
            Score history ({history.length} run{history.length !== 1 ? 's' : ''})
            {record?.BaselineMean != null && (
              <Text type="secondary" style={{ fontSize: 11, marginLeft: 8 }}>
                avg {record.BaselineMean.toFixed(1)}
                {record.ScoreDelta != null && (
                  <span style={{ marginLeft: 6, color: record.ScoreDelta >= 0 ? palette.success : palette.danger }}>
                    ({record.ScoreDelta >= 0 ? '+' : ''}{record.ScoreDelta.toFixed(1)})
                  </span>
                )}
              </Text>
            )}
          </Text>
          {loading ? <Spin size="small" /> : <Sparkline history={history} />}
        </div>

        {/* Navigation buttons */}
        <Space wrap>
          <Button
            size="small"
            icon={<EyeOutlined />}
            onClick={() =>
              window.open(
                `/episodes?entity=${encodeURIComponent(name)}&type=${type}`,
                '_blank',
              )
            }
          >
            Episodes ↗
          </Button>
          <Button
            size="small"
            icon={<HistoryOutlined />}
            onClick={() => navigateTo(name, type, '/history')}
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

        {/* Episode list */}
        <div>
          <Text strong style={{ fontSize: 12, display: 'block', marginBottom: 8 }}>
            Episodes ({loading ? '…' : episodes.length})
          </Text>
          {loading ? <Spin size="small" /> : <EpisodeList episodes={episodes} />}
        </div>

      </Space>
    </>
  )
}

// ── Hook ─────────────────────────────────────────────────────────────────────

export function useEntityDetailDrawer() {
  const [state, setState] = useState({ open: false, record: null })

  const openDetail = useCallback(
    (record) => setState({ open: true, record }),
    [],
  )
  const closeDetail = useCallback(
    () => setState({ open: false, record: null }),
    [],
  )

  const { name, type } = resolveEntity(state.record)

  const entityDetailDrawer = (
    <Drawer
      title={
        <Space size={8}>
          <Tag color={type === 'User' ? 'geekblue' : 'cyan'} style={{ margin: 0 }}>
            {type}
          </Tag>
          <Text strong style={{ fontSize: 14 }}>{name || '…'}</Text>
        </Space>
      }
      open={state.open}
      onClose={closeDetail}
      width={620}
      destroyOnClose
    >
      {state.open && state.record && (
        <DrawerContent record={state.record} />
      )}
    </Drawer>
  )

  return { openDetail, entityDetailDrawer }
}
