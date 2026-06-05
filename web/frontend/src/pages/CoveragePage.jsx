import React, { useEffect, useMemo, useState } from 'react'
import {
  Badge, Popover, Space, Spin, Table, Tabs, Tag, Tooltip, Typography,
} from 'antd'
import {
  ArrowDownOutlined, ArrowUpOutlined, LinkOutlined, MinusOutlined,
} from '@ant-design/icons'
import createPlotlyComponent from 'react-plotly.js/factory'
import Plotly from 'plotly.js-dist-min'
import { useNavigate } from 'react-router-dom'
import { api } from '../api'
import EmptyState from '../components/EmptyState'
import { darkPlot, palette } from '../theme'

const Plot = createPlotlyComponent(Plotly)
const { Text, Link } = Typography

// Status sort order: Silent floats to top, then Active, then Never seen
const STATUS_ORDER = { Silent: 0, Active: 1, 'Never seen': 2 }

// Color pool for behavior families (cycled by family index)
const FAMILY_COLORS = [
  palette.primary,   // #19C8FF
  palette.secondary, // #FF5A1F
  palette.success,   // #27D980
  palette.amber,     // #FFB84D
  '#722ed1',
  '#eb2f96',
  '#13c2c2',
  '#fa8c16',
  '#a0d911',
  '#1890ff',
]

function familyColorMap(detections) {
  const families = [...new Set(detections.map((d) => d.family))]
  const map = {}
  families.forEach((f, i) => { map[f] = FAMILY_COLORS[i % FAMILY_COLORS.length] })
  return map
}

function StatusBadge({ status }) {
  if (status === 'Active')     return <Badge status="success" text={<Text style={{ color: palette.success }}>Active</Text>} />
  if (status === 'Silent')     return <Badge status="warning" text={<Text style={{ color: palette.amber }}>Silent</Text>} />
  return <Badge status="default" text={<Text style={{ color: palette.muted }}>Never seen</Text>} />
}

function TrendIndicator({ dir, pct }) {
  if (!dir || dir === 'flat') return <MinusOutlined style={{ color: palette.muted }} />
  if (dir === 'up') {
    const label = pct != null ? `+${pct}%` : 'New'
    return <Space size={2}><ArrowUpOutlined style={{ color: palette.success }} /><Text style={{ color: palette.success, fontSize: 11 }}>{label}</Text></Space>
  }
  return <Space size={2}><ArrowDownOutlined style={{ color: palette.danger }} /><Text style={{ color: palette.danger, fontSize: 11 }}>{pct}%</Text></Space>
}

function TopDevicesContent({ devices, onNavigate }) {
  if (!devices?.length) return <Text type="secondary">No data</Text>
  return (
    <Space direction="vertical" size={4} style={{ minWidth: 220 }}>
      {devices.map((d) => (
        <Space key={d.device} style={{ justifyContent: 'space-between', width: '100%' }}>
          <Link onClick={() => onNavigate(d.device)} style={{ fontSize: 12 }}>
            <LinkOutlined style={{ marginRight: 4 }} />{d.device}
          </Link>
          <Text type="secondary" style={{ fontSize: 12 }}>{d.scenes} scenes</Text>
        </Space>
      ))}
    </Space>
  )
}

function formatLastSeen(ts) {
  if (!ts) return '—'
  try {
    const d = new Date(ts)
    return d.toLocaleDateString(undefined, { month: 'short', day: 'numeric', year: 'numeric' })
  } catch {
    return ts
  }
}

// ── Health Tab ───────────────────────────────────────────────────────────────

function HealthTab({ detections, totalRuns }) {
  const navigate = useNavigate()

  function goToEpisodes(device) {
    navigate(`/episodes?entity=${encodeURIComponent(device)}&type=Device`)
  }

  const sorted = useMemo(() =>
    [...detections].sort((a, b) => {
      const so = STATUS_ORDER[a.status] - STATUS_ORDER[b.status]
      if (so !== 0) return so
      return a.family.localeCompare(b.family)
    }),
    [detections]
  )

  const columns = [
    {
      title: 'Detection Type',
      dataIndex: 'detection_type',
      key: 'detection_type',
      width: 280,
      render: (v, row) => (
        <Popover
          content={<TopDevicesContent devices={row.top_devices} onNavigate={goToEpisodes} />}
          title={`Top devices — ${v}`}
          trigger="click"
          placement="right"
        >
          <Text style={{ cursor: 'pointer', color: palette.text }}>{v}</Text>
        </Popover>
      ),
    },
    {
      title: 'Family',
      dataIndex: 'family',
      key: 'family',
      width: 160,
      render: (v) => <Tag style={{ borderColor: palette.border, color: palette.muted, background: 'transparent' }}>{v}</Tag>,
    },
    {
      title: 'Status',
      dataIndex: 'status',
      key: 'status',
      width: 120,
      render: (v) => <StatusBadge status={v} />,
    },
    {
      title: 'Scenes',
      dataIndex: 'scene_count',
      key: 'scene_count',
      width: 80,
      align: 'right',
      render: (v) => v > 0 ? <Text>{v}</Text> : <Text type="secondary">—</Text>,
    },
    {
      title: 'Devices',
      dataIndex: 'device_count',
      key: 'device_count',
      width: 80,
      align: 'right',
      render: (v) => v > 0 ? <Text>{v}</Text> : <Text type="secondary">—</Text>,
    },
    {
      title: 'Last Seen',
      dataIndex: 'last_seen_ts',
      key: 'last_seen_ts',
      width: 140,
      render: (v) => <Text type="secondary" style={{ fontSize: 12 }}>{formatLastSeen(v)}</Text>,
    },
    {
      title: () => (
        <Tooltip title="Runs this detection has fired in vs total runs recorded">
          Runs Fired
        </Tooltip>
      ),
      key: 'runs_fired',
      width: 110,
      align: 'right',
      render: (_, row) =>
        totalRuns > 0
          ? <Text type="secondary" style={{ fontSize: 12 }}>{row.runs_fired} / {totalRuns}</Text>
          : <Text type="secondary">—</Text>,
    },
  ]

  const silentCount   = detections.filter((d) => d.status === 'Silent').length
  const activeCount   = detections.filter((d) => d.status === 'Active').length
  const neverCount    = detections.filter((d) => d.status === 'Never seen').length

  return (
    <Space direction="vertical" size={16} style={{ width: '100%' }}>
      <Space size={24}>
        <Space>
          <Badge status="warning" />
          <Text type="secondary">Silent: <Text style={{ color: palette.amber }}>{silentCount}</Text></Text>
        </Space>
        <Space>
          <Badge status="success" />
          <Text type="secondary">Active: <Text style={{ color: palette.success }}>{activeCount}</Text></Text>
        </Space>
        <Space>
          <Badge status="default" />
          <Text type="secondary">Never seen: <Text style={{ color: palette.muted }}>{neverCount}</Text></Text>
        </Space>
        {totalRuns > 0 && (
          <Text type="secondary" style={{ fontSize: 12 }}>{totalRuns} run{totalRuns !== 1 ? 's' : ''} in history</Text>
        )}
      </Space>

      <Table
        dataSource={sorted}
        columns={columns}
        rowKey="detection_type"
        size="small"
        pagination={false}
        rowClassName={(row) => row.status === 'Silent' ? 'row-silent' : ''}
        onRow={(row) => ({
          style: row.status === 'Silent'
            ? { background: 'rgba(255,184,77,0.04)' }
            : undefined,
        })}
      />
    </Space>
  )
}

// ── Landscape Tab ────────────────────────────────────────────────────────────

function LandscapeTab({ detections }) {
  const navigate = useNavigate()

  const active = useMemo(
    () => detections.filter((d) => d.device_count > 0).sort((a, b) => b.device_count - a.device_count),
    [detections]
  )

  const colorMap = useMemo(() => familyColorMap(detections), [detections])

  if (!active.length) {
    return (
      <EmptyState message="No active detections in current run" />
    )
  }

  const labels     = active.map((d) => d.detection_type)
  const xValues    = active.map((d) => d.device_count)
  const barColors  = active.map((d) => colorMap[d.family] || palette.muted)
  const barText    = active.map((d) => `${d.scene_count} scenes`)
  const hoverText  = active.map((d) => {
    const trend = d.trend_dir === 'up'
      ? `↑ ${d.trend_pct != null ? '+' + d.trend_pct + '%' : 'new'} vs last run`
      : d.trend_dir === 'down'
      ? `↓ ${d.trend_pct}% vs last run`
      : d.prev_device_count != null
      ? '→ unchanged vs last run'
      : 'no prior run to compare'
    return `<b>${d.detection_type}</b><br>Family: ${d.family}<br>Devices: ${d.device_count}<br>Scenes: ${d.scene_count}<br>${trend}`
  })

  // Trend annotation positions (just past the bar end)
  const trendTexts = active.map((d) => {
    if (!d.trend_dir || d.trend_dir === 'flat') return ''
    if (d.trend_dir === 'up')   return d.trend_pct != null ? `↑ +${d.trend_pct}%` : '↑ new'
    return `↓ ${d.trend_pct}%`
  })
  const trendColors = active.map((d) =>
    d.trend_dir === 'up' ? palette.success : d.trend_dir === 'down' ? palette.danger : palette.muted
  )

  const barTrace = {
    type:        'bar',
    orientation: 'h',
    y:           labels,
    x:           xValues,
    marker:      { color: barColors, opacity: 0.85 },
    text:        barText,
    textposition:'outside',
    textfont:    { color: palette.muted, size: 10 },
    hovertemplate: '%{customdata}<extra></extra>',
    customdata:  hoverText,
  }

  // Trend labels as a scatter-text trace placed at bar ends
  const trendTrace = {
    type:      'scatter',
    mode:      'text',
    orientation: 'h',
    y:         labels,
    x:         xValues.map((v, i) => v + Math.max(...xValues) * 0.01),
    text:      trendTexts,
    textfont:  { size: 10, color: trendColors },
    hoverinfo: 'none',
    showlegend: false,
  }

  // Legend: one dummy trace per family
  const legendTraces = Object.entries(colorMap).map(([fam, color]) => ({
    type:      'bar',
    orientation: 'h',
    x:         [null],
    y:         [null],
    name:      fam,
    marker:    { color },
    showlegend: true,
  }))

  const chartHeight = Math.max(300, active.length * 28 + 80)
  const maxX        = Math.max(...xValues)

  const layout = {
    ...darkPlot,
    height:    chartHeight,
    margin:    { l: 220, r: 80, t: 20, b: 40 },
    xaxis: {
      title:     { text: 'Devices (current run)', font: { color: palette.muted, size: 11 } },
      gridcolor: palette.border,
      color:     palette.muted,
      range:     [0, maxX * 1.25],
      fixedrange: true,
    },
    yaxis: {
      autorange:  'reversed',
      gridcolor:  palette.border,
      color:      palette.text,
      tickfont:   { size: 11 },
      fixedrange: true,
    },
    legend: {
      orientation: 'h',
      x: 0, y: -0.12,
      font: { color: palette.muted, size: 10 },
    },
    bargap:    0.3,
    hoverlabel: { bgcolor: '#0D1928', bordercolor: palette.border, font: { color: palette.text } },
  }

  return (
    <Plot
      data={[barTrace, trendTrace, ...legendTraces]}
      layout={layout}
      config={{ displayModeBar: false, responsive: true }}
      style={{ width: '100%' }}
      onClick={(ev) => {
        if (!ev.points?.length) return
        const dt = ev.points[0].y
        const det = active.find((d) => d.detection_type === dt)
        if (det?.top_devices?.[0]) {
          navigate(`/episodes?entity=${encodeURIComponent(det.top_devices[0].device)}&type=Device`)
        }
      }}
    />
  )
}

// ── Page root ────────────────────────────────────────────────────────────────

export default function CoveragePage() {
  const [data, setData]     = useState(null)
  const [loading, setLoading] = useState(true)
  const [error, setError]   = useState(null)

  useEffect(() => {
    api.coverage().then(({ data: d, error: e }) => {
      setLoading(false)
      if (e) { setError(e); return }
      setData(d)
    })
  }, [])

  if (loading) return <Spin style={{ display: 'block', marginTop: 80 }} />
  if (error)   return <EmptyState message={`Failed to load coverage data: ${error}`} />
  if (!data?.loaded) return <EmptyState message="No data loaded — run the pipeline first." />

  const { detections, total_runs } = data

  const tabs = [
    {
      key:      'health',
      label:    'Sensor Health',
      children: <HealthTab detections={detections} totalRuns={total_runs} />,
    },
    {
      key:      'landscape',
      label:    'Threat Landscape',
      children: <LandscapeTab detections={detections} />,
    },
  ]

  return (
    <Space direction="vertical" size={16} style={{ width: '100%' }}>
      <Typography.Title level={4} style={{ margin: 0, color: palette.text }}>
        Detection Coverage
      </Typography.Title>
      <Tabs items={tabs} defaultActiveKey="health" />
    </Space>
  )
}
