import React, { useEffect, useState } from 'react'
import { Card, Col, Empty, Row, Space, Spin, Statistic, Table, Tag, Typography } from 'antd'
import { AlertOutlined, ApartmentOutlined, ExclamationCircleOutlined, StopOutlined } from '@ant-design/icons'
import createPlotlyComponent from 'react-plotly.js/factory'
import Plotly from 'plotly.js-dist-min'
import { api } from '../api'
import EmptyState from '../components/EmptyState'
import { useApp } from '../context/AppContext'
import { darkPlot, palette, riskColor } from '../theme'

const Plot = createPlotlyComponent(Plotly)
const { Text } = Typography

const DARK = darkPlot

const PLOT_CFG = { responsive: true, displayModeBar: false }

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
const WF_COLORS = {
  Operational:          palette.success,
  AIWorkflow:           '#722ed1',
  DeveloperAutomation:  palette.primary,
}

function FlagTags({ record }) {
  const active = Object.keys(FLAG_COLORS).filter((f) => record[f])
  return (
    <Space size={2} wrap>
      {active.map((f) => (
        <Tag key={f} color={FLAG_COLORS[f]} style={{ fontSize: 10, padding: '0 4px' }}>
          {FLAG_LABELS[f]}
        </Tag>
      ))}
    </Space>
  )
}

const FLAGGED_COLS = [
  { title: 'Type',    dataIndex: 'EntityType',    key: 'EntityType',    width: 70 },
  {
    title: 'Entity',  dataIndex: 'EntityName',    key: 'EntityName',    ellipsis: true,
    render: (v) => <Text code style={{ fontSize: 11 }}>{v}</Text>,
  },
  {
    title: 'Score',   dataIndex: 'CompositeScore', key: 'CompositeScore', width: 75,
    sorter: (a, b) => (a.CompositeScore ?? 0) - (b.CompositeScore ?? 0),
    defaultSortOrder: 'descend',
    render: (v, r) => (
      <Text strong style={{ color: RISK_COLOR(r.TotalRisk ?? 0) }}>
        {(v ?? r.TotalRisk)?.toFixed(1) ?? '—'}
      </Text>
    ),
  },
  {
    title: 'Tactics', dataIndex: 'UniqueTactics', key: 'UniqueTactics', width: 65,
  },
  {
    title: 'Anomalies', key: 'flags',
    render: (_, r) => <FlagTags record={r} />,
  },
]

export default function InsightsPage() {
  const [data, setData]     = useState(null)
  const [loading, setLoading] = useState(true)
  const { pipelineStatus }  = useApp()

  useEffect(() => {
    setLoading(true)
    api.insights().then(({ data: d }) => {
      setData(d ?? null)
      setLoading(false)
    })
  }, [pipelineStatus.loaded_file])

  if (!loading && !pipelineStatus.is_loaded) return <EmptyState />
  if (loading || !data) {
    return <Spin size="large" style={{ display: 'block', textAlign: 'center', marginTop: 80 }} />
  }

  const {
    total_priority_cases = 0,
    high_risk_count      = 0,
    medium_risk_count    = 0,
    flagged_entity_count = 0,
    total_devices        = 0,
    total_users          = 0,
    suppressed_count     = 0,
    flag_counts          = {},
    tactic_distribution  = [],
    workflow_breakdown   = [],
    top_flagged          = [],
    history_trend        = [],
  } = data

  // ── Tactic coverage bar (horizontal) ───────────────────────────────────────
  const tacticChartData = [{
    type:        'bar',
    orientation: 'h',
    x:           tactic_distribution.map((d) => d.count),
    y:           tactic_distribution.map((d) => d.tactic),
    marker:      { color: palette.primary },
    hovertemplate: '%{y}: %{x} entities<extra></extra>',
  }]
  const tacticLayout = {
    ...DARK,
    margin: { t: 8, r: 20, b: 36, l: 170 },
    xaxis:  { gridcolor: palette.border, title: 'Entities' },
    yaxis:  { automargin: false },
    height: Math.max(220, tactic_distribution.length * 30 + 60),
  }

  // ── Workflow donut ─────────────────────────────────────────────────────────
  const wfChartData = [{
    type:     'pie',
    hole:     0.45,
    values:   workflow_breakdown.map((d) => d.count),
    labels:   workflow_breakdown.map((d) => d.class),
    marker:   { colors: workflow_breakdown.map((d) => WF_COLORS[d.class] ?? '#8c8c8c') },
    textinfo: 'percent',
    textposition: 'inside',
    hovertemplate: '%{label}: %{value} (%{percent})<extra></extra>',
  }]
  const wfLayout = {
    ...DARK,
    margin: { t: 8, r: 10, b: 10, l: 10 },
    legend: { orientation: 'h', y: -0.18, font: { size: 10 } },
    height: Math.max(220, tactic_distribution.length * 30 + 60),
  }

  // ── Historical risk trend ──────────────────────────────────────────────────
  const dates = history_trend.map((r) => r.run_date)

  const riskTrendData = [
    {
      type: 'scatter', mode: 'lines+markers',
      name: 'Total Risk',
      x: dates, y: history_trend.map((r) => r.total_risk),
      line:   { color: palette.danger, width: 2 },
      marker: { size: 5 },
      fill:      'tozeroy',
      fillcolor: 'rgba(255,77,77,0.07)',
    },
    {
      type: 'scatter', mode: 'lines+markers',
      name: 'Mean Score',
      x: dates, y: history_trend.map((r) => r.mean_score),
      line:   { color: palette.amber, width: 2, dash: 'dot' },
      marker: { size: 5 },
      yaxis:  'y2',
    },
    {
      type: 'scatter', mode: 'lines+markers',
      name: 'Mean HP',
      x: dates, y: history_trend.map((r) => r.mean_hp),
      line:   { color: '#b37feb', width: 2, dash: 'dashdot' },
      marker: { size: 5, symbol: 'diamond' },
      yaxis:  'y2',
    },
  ]
  const riskLayout = {
    ...DARK,
    margin: { t: 16, r: 70, b: 50, l: 60 },
    height: 270,
    xaxis:  { gridcolor: palette.border, title: 'Run date' },
    yaxis:  {
      gridcolor: palette.border, title: 'Total Risk',
      titlefont: { color: palette.danger }, tickfont: { color: palette.danger },
    },
    yaxis2: {
      title: 'Per-entity avg', overlaying: 'y', side: 'right', showgrid: false,
      titlefont: { color: palette.muted }, tickfont: { color: palette.muted },
    },
    legend: { orientation: 'h', y: -0.24 },
  }

  // ── Activity trend ─────────────────────────────────────────────────────────
  const activityData = [
    {
      type: 'scatter', mode: 'lines+markers',
      name: 'Entity Count',
      x: dates, y: history_trend.map((r) => r.entity_count),
      line:   { color: palette.success, width: 2 },
      marker: { size: 5 },
    },
    {
      type: 'scatter', mode: 'lines+markers',
      name: 'Avg Tactics',
      x: dates, y: history_trend.map((r) => r.mean_tactics),
      line:   { color: '#b37feb', width: 2, dash: 'dot' },
      marker: { size: 5 },
      yaxis:  'y2',
    },
  ]
  const activityLayout = {
    ...DARK,
    margin: { t: 16, r: 70, b: 50, l: 60 },
    height: 270,
    xaxis:  { gridcolor: palette.border, title: 'Run date' },
    yaxis:  {
      gridcolor: palette.border, title: 'Entities',
      titlefont: { color: palette.success }, tickfont: { color: palette.success },
    },
    yaxis2: {
      title: 'Avg Tactics', overlaying: 'y', side: 'right', showgrid: false,
      titlefont: { color: '#b37feb' }, tickfont: { color: '#b37feb' },
    },
    legend: { orientation: 'h', y: -0.24 },
  }

  const hasHistory = history_trend.length > 1

  return (
    <Space direction="vertical" size={16} style={{ width: '100%' }}>

      {/* ── KPI row ── */}
      <Row gutter={16}>
        <Col span={6}>
          <Card size="small">
            <Statistic
              title="Priority Cases"
              value={total_priority_cases}
              prefix={<ExclamationCircleOutlined />}
              valueStyle={{ color: palette.primary }}
            />
            <Space size={4} style={{ marginTop: 4 }}>
              {high_risk_count > 0 && (
                <Tag color="red" style={{ fontSize: 11 }}>{high_risk_count} high ≥50</Tag>
              )}
              {medium_risk_count > 0 && (
                <Tag color="orange" style={{ fontSize: 11 }}>{medium_risk_count} med ≥20</Tag>
              )}
            </Space>
          </Card>
        </Col>

        <Col span={6}>
          <Card size="small">
            <Statistic
              title="Flagged Entities"
              value={flagged_entity_count}
              prefix={<AlertOutlined />}
              valueStyle={{ color: flagged_entity_count > 0 ? palette.secondary : palette.success }}
            />
            <Space size={2} wrap style={{ marginTop: 4 }}>
              {Object.entries(flag_counts)
                .filter(([, v]) => v > 0)
                .map(([f, v]) => (
                  <Tag key={f} color={FLAG_COLORS[f]} style={{ fontSize: 10, padding: '0 4px' }}>
                    {FLAG_LABELS[f]} {v}
                  </Tag>
                ))}
            </Space>
          </Card>
        </Col>

        <Col span={6}>
          <Card size="small">
            <Statistic
              title="Active Scope"
              value={total_devices + total_users}
              prefix={<ApartmentOutlined />}
              valueStyle={{ color: palette.text }}
            />
            <Text type="secondary" style={{ fontSize: 11 }}>
              {total_devices} devices · {total_users} users
            </Text>
          </Card>
        </Col>

        <Col span={6}>
          <Card size="small">
            <Statistic
              title="Suppressed"
              value={suppressed_count}
              prefix={<StopOutlined />}
              valueStyle={{ color: suppressed_count > 0 ? palette.muted : palette.success }}
            />
          </Card>
        </Col>
      </Row>

      {/* ── Tactic coverage + workflow ── */}
      <Row gutter={16} align="stretch">
        <Col span={16}>
          <Card size="small" title="Tactic Coverage" style={{ height: '100%' }}>
            {tactic_distribution.length > 0 ? (
              <Plot
                data={tacticChartData}
                layout={tacticLayout}
                config={PLOT_CFG}
                style={{ width: '100%' }}
              />
            ) : (
              <Empty description="No tactic data" style={{ padding: 40 }} />
            )}
          </Card>
        </Col>
        <Col span={8}>
          <Card size="small" title="Workflow Classes" style={{ height: '100%' }}>
            {workflow_breakdown.length > 0 ? (
              <Plot
                data={wfChartData}
                layout={wfLayout}
                config={PLOT_CFG}
                style={{ width: '100%' }}
              />
            ) : (
              <Empty description="No workflow data" style={{ padding: 40 }} />
            )}
          </Card>
        </Col>
      </Row>

      {/* ── Historical trend charts ── */}
      {hasHistory ? (
        <Row gutter={16}>
          <Col span={12}>
            <Card size="small" title="Environment Risk Trend">
              <Plot
                data={riskTrendData}
                layout={riskLayout}
                config={PLOT_CFG}
                style={{ width: '100%' }}
              />
            </Card>
          </Col>
          <Col span={12}>
            <Card size="small" title="Entity Activity">
              <Plot
                data={activityData}
                layout={activityLayout}
                config={PLOT_CFG}
                style={{ width: '100%' }}
              />
            </Card>
          </Col>
        </Row>
      ) : (
        <Card size="small" title="Historical Trends">
          <Empty description="Historical trends will appear after 2+ pipeline runs" style={{ padding: 24 }} />
        </Card>
      )}

      {/* ── Top flagged entities ── */}
      {top_flagged.length > 0 && (
        <Card size="small" title="Top Flagged Entities">
          <Table
            dataSource={top_flagged}
            columns={FLAGGED_COLS}
            rowKey={(r) => `${r.EntityType}-${r.EntityName}`}
            size="small"
            pagination={false}
          />
        </Card>
      )}

    </Space>
  )
}
