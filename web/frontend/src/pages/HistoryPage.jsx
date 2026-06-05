/**
 * Historical Trends — insightful landing (stats + sortable entity list) that
 * transitions into a per-entity score chart when a row is clicked.
 */

import React, { useEffect, useMemo, useState } from 'react'
import {
  Button, Card, Col, Input, Row, Space, Spin, Statistic, Table, Tag, Tooltip, Typography,
} from 'antd'
import {
  ArrowLeftOutlined, ArrowDownOutlined, ArrowUpOutlined,
  MinusOutlined, SearchOutlined,
} from '@ant-design/icons'
import createPlotlyComponent from 'react-plotly.js/factory'
import Plotly from 'plotly.js-dist-min'
import { api } from '../api'
import EmptyState from '../components/EmptyState'
import { useApp } from '../context/AppContext'
import { darkPlot, palette, riskColor as RISK_COLOR } from '../theme'

const Plot = createPlotlyComponent(Plotly)
const { Text } = Typography

// ── Anomaly config (shared between landing and chart view) ───────────────────

const ANOMALY = {
  IsScoreSpike:      { color: palette.danger,    symbol: 'star',        label: 'Spike',     tip: 'Score >2.5× above historical mean' },
  IsNewHigh:         { color: palette.secondary, symbol: 'triangle-up', label: 'NewHigh',   tip: 'All-time highest score for this entity' },
  IsTacticExpansion: { color: '#722ed1',         symbol: 'diamond',     label: 'TacticExp', tip: 'More distinct tactics than ever before' },
  IsAdaptingTactics: { color: '#eb2f96',         symbol: 'cross',       label: 'Adapting',  tip: 'New MITRE tactic not seen in any prior run' },
  IsEmergingEntity:  { color: '#13c2c2',         symbol: 'circle',      label: 'Emerging',  tip: 'Newly appeared entity with elevated score' },
}

// ── Mini inline sparkline ────────────────────────────────────────────────────

function MiniSparkline({ scores, latestScore }) {
  if (!scores?.length) return <Text type="secondary" style={{ fontSize: 10 }}>—</Text>
  const W = 90, H = 24, PAD = 2
  const min = Math.min(...scores)
  const max = Math.max(...scores)
  const range = max - min || 1
  const pts = scores.map((s, i) => ({
    x: PAD + (i / Math.max(scores.length - 1, 1)) * (W - PAD * 2),
    y: H - PAD - ((s - min) / range) * (H - PAD * 2),
  }))
  const polyPts = pts.map((p) => `${p.x},${p.y}`).join(' ')
  const last = pts[pts.length - 1]
  return (
    <svg width={W} height={H} style={{ display: 'block' }}>
      <polyline
        points={polyPts}
        fill="none"
        stroke={palette.primary}
        strokeWidth={1.5}
        strokeLinejoin="round"
        strokeLinecap="round"
        opacity={0.7}
      />
      <circle cx={last.x} cy={last.y} r={3} fill={RISK_COLOR(latestScore ?? 0)} />
    </svg>
  )
}

// ── Anomaly flag badges ───────────────────────────────────────────────────────

function FlagBadges({ record }) {
  const flags = Object.entries(ANOMALY).filter(([k]) => record[k])
  if (!flags.length) return null
  return (
    <Space size={2} wrap>
      {flags.map(([, cfg]) => (
        <Tooltip key={cfg.label} title={cfg.tip}>
          <Tag
            color={cfg.color}
            style={{ fontSize: 10, padding: '0 4px', margin: 0, cursor: 'default' }}
          >
            {cfg.label}
          </Tag>
        </Tooltip>
      ))}
    </Space>
  )
}

// ── Delta cell ───────────────────────────────────────────────────────────────

function DeltaCell({ delta }) {
  if (delta == null) return <Text type="secondary" style={{ fontSize: 11 }}>—</Text>
  const color = delta > 0 ? palette.danger : delta < 0 ? palette.success : palette.muted
  const Icon = delta > 0 ? ArrowUpOutlined : delta < 0 ? ArrowDownOutlined : MinusOutlined
  return (
    <Space size={2}>
      <Icon style={{ color, fontSize: 10 }} />
      <Text style={{ fontSize: 11, color }}>{delta > 0 ? `+${delta}` : delta}</Text>
    </Space>
  )
}

// ── Stats header ─────────────────────────────────────────────────────────────

function StatsHeader({ meta, loading }) {
  if (loading) return <Spin size="small" style={{ display: 'block', marginBottom: 16 }} />
  if (!meta?.TotalEntities) return null
  return (
    <Row gutter={12} style={{ marginBottom: 20 }}>
      {[
        {
          title: 'Entities tracked',
          value: meta.TotalEntities,
          suffix: null,
          tip: 'Total devices and users that have appeared in at least one hunt run',
        },
        {
          title: 'Active anomalies',
          value: meta.EntitiesWithFlags,
          suffix: null,
          valueStyle: { color: meta.EntitiesWithFlags > 0 ? palette.danger : palette.success },
          tip: 'Entities with at least one anomaly flag in their latest run',
        },
        {
          title: 'Trending up',
          value: meta.TrendingUp,
          suffix: null,
          valueStyle: { color: meta.TrendingUp > 0 ? palette.secondary : undefined },
          tip: 'Entities whose score increased since the previous run',
        },
        {
          title: 'Trending down',
          value: meta.TrendingDown,
          suffix: null,
          valueStyle: { color: meta.TrendingDown > 0 ? palette.success : undefined },
          tip: 'Entities whose score decreased since the previous run',
        },
        {
          title: 'Latest run',
          value: meta.LatestRunDate ?? '—',
          suffix: null,
          tip: 'Date of the most recent hunt run stored in the history database',
        },
      ].map(({ title, value, valueStyle, tip }) => (
        <Col key={title} xs={12} sm={8} md={5} lg={5}>
          <Tooltip title={tip}>
            <Card size="small" style={{ textAlign: 'center', cursor: 'default' }}>
              <Statistic
                title={<Text style={{ fontSize: 11 }}>{title}</Text>}
                value={value}
                valueStyle={{ fontSize: 20, ...(valueStyle ?? {}) }}
              />
            </Card>
          </Tooltip>
        </Col>
      ))}
    </Row>
  )
}

// ── Sort helpers ──────────────────────────────────────────────────────────────

const SORT_MODES = [
  { label: 'Most Anomalous', value: 'anomalous' },
  { label: 'Highest Risk',   value: 'risk' },
  { label: 'Biggest Jump',   value: 'jump' },
]

function applySortMode(rows, mode) {
  const copy = [...rows]
  if (mode === 'anomalous') {
    copy.sort((a, b) => {
      const fd = b.FlagCount - a.FlagCount
      if (fd !== 0) return fd
      return (b.ZScore ?? -Infinity) - (a.ZScore ?? -Infinity)
    })
  } else if (mode === 'risk') {
    copy.sort((a, b) => b.LatestScore - a.LatestScore)
  } else {
    copy.sort((a, b) => (b.ZScore ?? -Infinity) - (a.ZScore ?? -Infinity))
  }
  return copy
}

// ── Entity landing table ──────────────────────────────────────────────────────

const LANDING_COLUMNS = [
  {
    title: 'Type',
    dataIndex: 'EntityType',
    key: 'EntityType',
    width: 70,
    filters: [
      { text: 'Device', value: 'Device' },
      { text: 'User',   value: 'User' },
    ],
    onFilter: (v, r) => r.EntityType === v,
    render: (v) => <Tag color={v === 'User' ? 'geekblue' : 'cyan'} style={{ margin: 0 }}>{v}</Tag>,
  },
  {
    title: 'Entity',
    dataIndex: 'EntityName',
    key: 'EntityName',
    ellipsis: true,
    render: (v) => <Text code style={{ fontSize: 12 }}>{v}</Text>,
  },
  {
    title: 'Score',
    dataIndex: 'LatestScore',
    key: 'LatestScore',
    width: 80,
    sorter: (a, b) => a.LatestScore - b.LatestScore,
    render: (v) => (
      <Text strong style={{ color: RISK_COLOR(v ?? 0) }}>{v?.toFixed(1) ?? '—'}</Text>
    ),
  },
  {
    title: <Tooltip title="Score change vs previous run"><span>Δ</span></Tooltip>,
    dataIndex: 'ScoreDelta',
    key: 'ScoreDelta',
    width: 75,
    sorter: (a, b) => (a.ScoreDelta ?? 0) - (b.ScoreDelta ?? 0),
    render: (v) => <DeltaCell delta={v} />,
  },
  {
    title: 'Anomalies',
    key: 'flags',
    width: 220,
    filters: Object.entries(ANOMALY).map(([k, cfg]) => ({ text: cfg.label, value: k })),
    onFilter: (v, r) => !!r[v],
    render: (_, r) => <FlagBadges record={r} />,
  },
  {
    title: <Tooltip title="Score trend over last 10 runs"><span>Trend</span></Tooltip>,
    key: 'sparkline',
    width: 100,
    render: (_, r) => <MiniSparkline scores={r.Sparkline} latestScore={r.LatestScore} />,
  },
  {
    title: 'Runs',
    dataIndex: 'RunCount',
    key: 'RunCount',
    width: 60,
    sorter: (a, b) => a.RunCount - b.RunCount,
  },
  {
    title: 'First → Last seen',
    key: 'seen',
    width: 190,
    render: (_, r) => (
      <Text style={{ fontSize: 11 }} type="secondary">
        {r.FirstSeen ?? '—'} → {r.LastSeen ?? '—'}
      </Text>
    ),
  },
]

function EntityLanding({ entities, loading, sortMode, setSortMode, onSelect }) {
  const [search, setSearch] = useState('')

  const filtered = useMemo(() => {
    const sorted = applySortMode(entities, sortMode)
    if (!search) return sorted
    const q = search.toLowerCase()
    return sorted.filter(
      (r) => r.EntityName?.toLowerCase().includes(q) || r.EntityType?.toLowerCase().includes(q),
    )
  }, [entities, sortMode, search])

  return (
    <>
      <Space style={{ marginBottom: 12 }} wrap>
        {SORT_MODES.map((m) => (
          <Button
            key={m.value}
            type={sortMode === m.value ? 'primary' : 'default'}
            size="small"
            onClick={() => setSortMode(m.value)}
          >
            {m.label}
          </Button>
        ))}
        <Input
          prefix={<SearchOutlined />}
          placeholder="Search entity…"
          value={search}
          onChange={(e) => setSearch(e.target.value)}
          allowClear
          style={{ width: 220 }}
          size="small"
        />
        <Text type="secondary" style={{ fontSize: 12 }}>
          {filtered.length} of {entities.length} entities
        </Text>
      </Space>
      <Table
        dataSource={filtered}
        columns={LANDING_COLUMNS}
        rowKey={(r) => `${r.EntityType}:${r.EntityName}`}
        loading={loading}
        size="small"
        pagination={{ pageSize: 25, showSizeChanger: true, pageSizeOptions: ['25', '50', '100'] }}
        onRow={(r) => ({
          onClick: () => onSelect({ name: r.EntityName, type: r.EntityType }),
          style: { cursor: 'pointer' },
        })}
        scroll={{ x: 900 }}
      />
    </>
  )
}

// ── Per-entity chart view ────────────────────────────────────────────────────

function EntityChart({ selected }) {
  const [history, setHistory] = useState([])
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    if (!selected) return
    setLoading(true)
    api.entityHistory(selected.type, selected.name).then(({ data: d }) => {
      setHistory(d?.data ?? [])
      setLoading(false)
    })
  }, [selected])

  const traces = useMemo(() => {
    if (!history.length) return []
    const x = history.map((r) => r.RunTimestamp?.slice(0, 10))
    const y = history.map((r) => r.SeasonScore)
    const main = {
      type: 'scatter', mode: 'lines+markers', name: 'Risk score', x, y,
      line: { color: palette.primary, width: 2 },
      marker: { color: palette.primary, size: 5 },
    }
    const flagTraces = Object.entries(ANOMALY).map(([flag, cfg]) => {
      const pts = history.filter((r) => r[flag])
      return {
        type: 'scatter', mode: 'markers', name: cfg.label,
        x: pts.map((r) => r.RunTimestamp?.slice(0, 10)),
        y: pts.map((r) => r.SeasonScore),
        marker: { color: cfg.color, symbol: cfg.symbol, size: 12 },
      }
    })
    return [main, ...flagTraces]
  }, [history])

  const layout = {
    ...darkPlot,
    font: { color: palette.text, size: 12 },
    xaxis: { gridcolor: palette.border, title: 'Run date' },
    yaxis: { gridcolor: palette.border, title: 'Risk score' },
    legend: { orientation: 'h', y: -0.2 },
    margin: { t: 20, r: 20, b: 60, l: 60 },
  }

  if (loading) return <Spin size="large" style={{ display: 'block', marginTop: 60 }} />
  if (!history.length) return <Text type="secondary">No history found for {selected.name}</Text>

  const last = history[history.length - 1]
  const activeFlags = Object.entries(ANOMALY).filter(([f]) => last[f])

  return (
    <Row gutter={16}>
      <Col span={18}>
        <Plot
          data={traces}
          layout={layout}
          config={{ responsive: true, displayModeBar: false }}
          style={{ width: '100%', height: 400 }}
        />
      </Col>
      <Col span={6}>
        <Card size="small" title="Latest run" style={{ marginBottom: 12 }}>
          <Space direction="vertical" size={4}>
            <Text>Score: <Text strong style={{ color: RISK_COLOR(last.SeasonScore ?? 0) }}>{last.SeasonScore?.toFixed(1)}</Text></Text>
            <Text>Episodes: {last.EpisodeCount}</Text>
            <Text>Tactics: {last.UniqueTactics}</Text>
            <Text>Top tactic: {last.TopTactic || '—'}</Text>
            <Text>Top family: {last.TopBehaviorFamily || '—'}</Text>
            {activeFlags.length > 0 && (
              <div style={{ marginTop: 8 }}>
                {activeFlags.map(([, cfg]) => (
                  <Tag key={cfg.label} color={cfg.color} style={{ marginBottom: 4 }}>{cfg.label}</Tag>
                ))}
              </div>
            )}
          </Space>
        </Card>
        <Card size="small" title="Legend">
          <Space direction="vertical" size={2}>
            {Object.values(ANOMALY).map((cfg) => (
              <Tooltip key={cfg.label} title={cfg.tip} placement="left">
                <Space size={6} style={{ cursor: 'default' }}>
                  <div style={{ width: 12, height: 12, background: cfg.color, borderRadius: 2 }} />
                  <Text style={{ fontSize: 11 }}>{cfg.label}</Text>
                </Space>
              </Tooltip>
            ))}
          </Space>
        </Card>
      </Col>
    </Row>
  )
}

// ── Page root ────────────────────────────────────────────────────────────────

export default function HistoryPage() {
  const [entities, setEntities] = useState([])
  const [meta, setMeta] = useState({})
  const [loadingList, setLoadingList] = useState(true)
  const [selected, setSelected] = useState(null)
  const [sortMode, setSortMode] = useState('anomalous')
  const { pipelineStatus, selectedEntity, setSelectedEntity } = useApp()

  useEffect(() => {
    setLoadingList(true)
    api.historyList().then(({ data: d }) => {
      setEntities(d?.data ?? [])
      setMeta(d?.meta ?? {})
      setLoadingList(false)
    })
  }, [pipelineStatus.loaded_file])

  // Cross-module navigation (e.g. "History" button in detail drawer)
  useEffect(() => {
    if (selectedEntity) {
      setSelected(selectedEntity)
      setSelectedEntity(null)
    }
  }, [selectedEntity, setSelectedEntity])

  if (!loadingList && !pipelineStatus.is_loaded) return <EmptyState />

  // ── Chart view ──────────────────────────────────────────────────────────────
  if (selected) {
    return (
      <div>
        <Space style={{ marginBottom: 16 }} align="center">
          <Button
            icon={<ArrowLeftOutlined />}
            onClick={() => setSelected(null)}
            size="small"
          >
            Overview
          </Button>
          <Tag color={selected.type === 'User' ? 'geekblue' : 'cyan'} style={{ margin: 0 }}>
            {selected.type}
          </Tag>
          <Text strong style={{ fontSize: 14 }}>{selected.name}</Text>
        </Space>
        <EntityChart selected={selected} />
      </div>
    )
  }

  // ── Landing view ────────────────────────────────────────────────────────────
  return (
    <div>
      <StatsHeader meta={meta} loading={loadingList} />
      <EntityLanding
        entities={entities}
        loading={loadingList}
        sortMode={sortMode}
        setSortMode={setSortMode}
        onSelect={setSelected}
      />
    </div>
  )
}
