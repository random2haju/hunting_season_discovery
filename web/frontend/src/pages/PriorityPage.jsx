import React, { useCallback, useEffect, useMemo, useState } from 'react'
import { Input, Select, Space, Table, Tag, Tooltip, Typography } from 'antd'
import { SearchOutlined } from '@ant-design/icons'
import { api } from '../api'
import EmptyState from '../components/EmptyState'
import { useEntityContextMenu } from '../components/EntityContextMenu'
import { useEntityDetailDrawer } from '../components/EntityDetailDrawer'
import { useApp } from '../context/AppContext'
import { palette, riskColor as RISK_COLOR } from '../theme'

const { Text } = Typography

const FLAG_COLORS = {
  IsScoreSpike:     'red',
  IsNewHigh:        'orange',
  IsTacticExpansion:'purple',
  IsAdaptingTactics:'magenta',
  IsEmergingEntity: 'cyan',
}

const FLAG_LABELS = {
  IsScoreSpike:     'Spike',
  IsNewHigh:        'NewHigh',
  IsTacticExpansion:'TacticExp',
  IsAdaptingTactics:'Adapting',
  IsEmergingEntity: 'Emerging',
}

function AnomalyFlags({ record }) {
  const flags = Object.keys(FLAG_COLORS).filter((f) => record[f])
  return (
    <Space size={2} wrap>
      {flags.map((f) => (
        <Tag key={f} color={FLAG_COLORS[f]} style={{ fontSize: 10, padding: '0 4px' }}>
          {FLAG_LABELS[f]}
        </Tag>
      ))}
    </Space>
  )
}

const COLUMNS = [
  {
    title: 'Type',
    dataIndex: 'EntityType',
    key: 'EntityType',
    width: 70,
    filters: [
      { text: 'Device', value: 'Device' },
      { text: 'User', value: 'User' },
    ],
    onFilter: (v, r) => r.EntityType === v,
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
    dataIndex: 'CompositeScore',
    key: 'CompositeScore',
    width: 80,
    sorter: (a, b) => (a.CompositeScore ?? a.TotalRisk ?? 0) - (b.CompositeScore ?? b.TotalRisk ?? 0),
    defaultSortOrder: 'descend',
    render: (v, r) => (
      <Tooltip title={`Risk ${r.TotalRisk?.toFixed(1) ?? '—'} + HP ${r.HistoricalPriority?.toFixed(1) ?? '0'}`}>
        <Text strong style={{ color: RISK_COLOR(r.TotalRisk ?? 0) }}>
          {(v ?? r.TotalRisk)?.toFixed(1) ?? '—'}
        </Text>
      </Tooltip>
    ),
  },
  {
    title: 'Risk',
    dataIndex: 'TotalRisk',
    key: 'TotalRisk',
    width: 75,
    sorter: (a, b) => (a.TotalRisk ?? 0) - (b.TotalRisk ?? 0),
    render: (v) => <Text style={{ fontSize: 11, color: RISK_COLOR(v ?? 0) }}>{v?.toFixed(1) ?? '—'}</Text>,
  },
  {
    title: 'HP',
    dataIndex: 'HistoricalPriority',
    key: 'HistoricalPriority',
    width: 60,
    sorter: (a, b) => (a.HistoricalPriority ?? 0) - (b.HistoricalPriority ?? 0),
    render: (v) => v != null && v > 0
      ? <Text style={{ fontSize: 11, color: palette.primary }}>{v.toFixed(1)}</Text>
      : <Text type="secondary" style={{ fontSize: 11 }}>—</Text>,
  },
  {
    title: 'Pct',
    dataIndex: 'RiskPercentile',
    key: 'RiskPercentile',
    width: 55,
    render: (v) => (v != null ? `${v}%` : '—'),
  },
  {
    title: 'Tactics',
    dataIndex: 'UniqueTactics',
    key: 'UniqueTactics',
    width: 70,
    sorter: (a, b) => (a.UniqueTactics ?? 0) - (b.UniqueTactics ?? 0),
  },
  {
    title: 'Tactic Set',
    dataIndex: 'TacticSet',
    key: 'TacticSet',
    ellipsis: true,
    render: (v) => <Tooltip title={v}><Text style={{ fontSize: 11 }}>{v}</Text></Tooltip>,
  },
  {
    title: 'Workflow',
    dataIndex: 'PrimaryWorkflowClass',
    key: 'PrimaryWorkflowClass',
    width: 120,
    filters: [
      { text: 'Operational', value: 'Operational' },
      { text: 'AIWorkflow', value: 'AIWorkflow' },
      { text: 'DeveloperAutomation', value: 'DeveloperAutomation' },
    ],
    onFilter: (v, r) => r.PrimaryWorkflowClass === v,
  },
  {
    title: 'AI%',
    dataIndex: 'AIWorkflowScenePct',
    key: 'AIWorkflowScenePct',
    width: 60,
    sorter: (a, b) => (a.AIWorkflowScenePct ?? 0) - (b.AIWorkflowScenePct ?? 0),
    render: (v) => v != null ? (
      <Text style={{ fontSize: 11, color: v === 0 ? palette.danger : v >= 50 ? palette.success : palette.secondary }}>
        {v}%
      </Text>
    ) : '—',
  },
  {
    title: 'Episodes',
    dataIndex: 'EpisodeCount',
    key: 'EpisodeCount',
    width: 80,
    sorter: (a, b) => (a.EpisodeCount ?? 0) - (b.EpisodeCount ?? 0),
  },
  {
    title: 'Anomalies',
    key: 'anomalies',
    width: 200,
    render: (_, r) => <AnomalyFlags record={r} />,
    filters: Object.keys(FLAG_COLORS).map((f) => ({ text: FLAG_LABELS[f], value: f })),
    onFilter: (v, r) => !!r[v],
  },
]

export default function PriorityPage() {
  const [data, setData] = useState([])
  const [loading, setLoading] = useState(true)
  const [search, setSearch] = useState('')
  const [tacticFilter, setTacticFilter] = useState([])
  const { pipelineStatus } = useApp()
  const { openDetail, entityDetailDrawer } = useEntityDetailDrawer()
  const { onRow, contextMenuPortal, suppressModal } = useEntityContextMenu({ onViewDetails: openDetail })

  const tableOnRow = useCallback(
    (record) => ({
      ...onRow(record),
      onClick: () => openDetail(record),
      style: { cursor: 'pointer' },
    }),
    [onRow, openDetail],
  )

  useEffect(() => {
    setLoading(true)
    api.priorityCases().then(({ data: d }) => {
      setData(d?.data ?? [])
      setLoading(false)
    })
  }, [pipelineStatus.loaded_file])

  const allTactics = useMemo(() => {
    const set = new Set()
    data.forEach((r) => {
      if (r.TacticSet) r.TacticSet.split(',').forEach((t) => { const s = t.trim(); if (s) set.add(s) })
    })
    return [...set].sort()
  }, [data])

  const filtered = useMemo(() => {
    let result = data
    if (search) {
      const q = search.toLowerCase()
      result = result.filter(
        (r) => r.EntityName?.toLowerCase().includes(q) || r.TacticSet?.toLowerCase().includes(q),
      )
    }
    if (tacticFilter.length > 0) {
      result = result.filter((r) => {
        const tactics = (r.TacticSet ?? '').split(',').map((t) => t.trim())
        return tacticFilter.every((t) => tactics.includes(t))
      })
    }
    return result
  }, [data, search, tacticFilter])

  if (!loading && !pipelineStatus.is_loaded) return <EmptyState />

  return (
    <>
      {contextMenuPortal}
      {suppressModal}
      {entityDetailDrawer}
      <Space style={{ marginBottom: 12 }} wrap>
        <Input
          prefix={<SearchOutlined />}
          placeholder="Search entity or tactic…"
          value={search}
          onChange={(e) => setSearch(e.target.value)}
          allowClear
          style={{ width: 240 }}
        />
        <Select
          mode="multiple"
          allowClear
          placeholder="Filter by tactic…"
          value={tacticFilter}
          onChange={setTacticFilter}
          options={allTactics.map((t) => ({ label: t, value: t }))}
          style={{ minWidth: 220 }}
          maxTagCount={2}
        />
        <Text type="secondary" style={{ fontSize: 12 }}>
          {filtered.length} case{filtered.length !== 1 ? 's' : ''}
          {(search || tacticFilter.length > 0) ? ` (filtered from ${data.length})` : ''}
        </Text>
      </Space>
      <Table
        dataSource={filtered}
        columns={COLUMNS}
        rowKey={(r) => `${r.EntityType}-${r.EntityName}`}
        loading={loading}
        size="small"
        pagination={{ pageSize: 50, showSizeChanger: true }}
        onRow={tableOnRow}
        scroll={{ x: 1000 }}
      />
    </>
  )
}
