import React, { useCallback, useEffect, useMemo, useState } from 'react'
import { Input, Space, Table, Tag, Tooltip, Typography } from 'antd'
import { SearchOutlined } from '@ant-design/icons'
import { api } from '../api'
import EmptyState from '../components/EmptyState'
import { useEntityContextMenu } from '../components/EntityContextMenu'
import { useEntityDetailDrawer } from '../components/EntityDetailDrawer'
import { useApp } from '../context/AppContext'

const { Text } = Typography

const RISK_COLOR = (v) =>
  v >= 50 ? '#ff4d4f' : v >= 20 ? '#fa8c16' : v >= 5 ? '#faad14' : '#52c41a'

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
    title: 'Risk',
    dataIndex: 'TotalRisk',
    key: 'TotalRisk',
    width: 90,
    sorter: (a, b) => (a.TotalRisk ?? 0) - (b.TotalRisk ?? 0),
    defaultSortOrder: 'descend',
    render: (v) => (
      <Text strong style={{ color: RISK_COLOR(v ?? 0) }}>
        {v?.toFixed(1) ?? '—'}
      </Text>
    ),
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
      <Text style={{ fontSize: 11, color: v === 0 ? '#ff4d4f' : v >= 50 ? '#52c41a' : '#fa8c16' }}>
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

  const filtered = useMemo(() => {
    if (!search) return data
    const q = search.toLowerCase()
    return data.filter(
      (r) =>
        r.EntityName?.toLowerCase().includes(q) ||
        r.TacticSet?.toLowerCase().includes(q),
    )
  }, [data, search])

  if (!loading && !pipelineStatus.is_loaded) return <EmptyState />

  return (
    <>
      {contextMenuPortal}
      {suppressModal}
      {entityDetailDrawer}
      <Space style={{ marginBottom: 12 }}>
        <Input
          prefix={<SearchOutlined />}
          placeholder="Search entity or tactic…"
          value={search}
          onChange={(e) => setSearch(e.target.value)}
          allowClear
          style={{ width: 280 }}
        />
        <Text type="secondary" style={{ fontSize: 12 }}>
          {filtered.length} case{filtered.length !== 1 ? 's' : ''}
          {search ? ` (filtered from ${data.length})` : ''}
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
