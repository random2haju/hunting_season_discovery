import React, { useEffect, useMemo, useState } from 'react'
import { Input, Radio, Space, Table, Tag, Tooltip, Typography } from 'antd'
import { SearchOutlined } from '@ant-design/icons'
import { api } from '../api'
import EmptyState from '../components/EmptyState'
import { useEntityContextMenu } from '../components/EntityContextMenu'
import { useApp } from '../context/AppContext'

const { Text } = Typography

const RISK_COLOR = (v) =>
  v >= 50 ? '#ff4d4f' : v >= 20 ? '#fa8c16' : v >= 5 ? '#faad14' : '#52c41a'

const FLAG_LABELS = {
  IsScoreSpike: 'Spike', IsNewHigh: 'NewHigh',
  IsTacticExpansion: 'TacticExp', IsAdaptingTactics: 'Adapting', IsEmergingEntity: 'Emerging',
}
const FLAG_COLORS = {
  IsScoreSpike: 'red', IsNewHigh: 'orange',
  IsTacticExpansion: 'purple', IsAdaptingTactics: 'magenta', IsEmergingEntity: 'cyan',
}

function makeColumns(entityCol) {
  return [
    {
      title: 'Entity',
      dataIndex: entityCol,
      key: entityCol,
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
        <Text strong style={{ color: RISK_COLOR(v ?? 0) }}>{v?.toFixed(1) ?? '—'}</Text>
      ),
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
      width: 140,
      filters: [
        { text: 'Operational', value: 'Operational' },
        { text: 'AIWorkflow', value: 'AIWorkflow' },
        { text: 'DeveloperAutomation', value: 'DeveloperAutomation' },
      ],
      onFilter: (v, r) => r.PrimaryWorkflowClass === v,
    },
    {
      title: 'Eligible',
      dataIndex: 'EligibleForPriority',
      key: 'EligibleForPriority',
      width: 75,
      filters: [
        { text: 'Yes', value: true },
        { text: 'No', value: false },
      ],
      onFilter: (v, r) => !!r.EligibleForPriority === v,
      render: (v) =>
        v ? <Tag color="green">Yes</Tag> : <Tag color="default">No</Tag>,
    },
    {
      title: 'Suppressed',
      dataIndex: 'IsSuppressed',
      key: 'IsSuppressed',
      width: 95,
      filters: [
        { text: 'Yes', value: true },
        { text: 'No', value: false },
      ],
      onFilter: (v, r) => !!r.IsSuppressed === v,
      render: (v, r) =>
        v ? <Tooltip title={r.SuppressReason}><Tag color="red">Yes</Tag></Tooltip> : null,
    },
    {
      title: 'Episodes',
      dataIndex: 'EpisodeCount',
      key: 'EpisodeCount',
      width: 80,
      sorter: (a, b) => (a.EpisodeCount ?? 0) - (b.EpisodeCount ?? 0),
    },
    {
      title: 'ZScore',
      dataIndex: 'ZScore',
      key: 'ZScore',
      width: 75,
      sorter: (a, b) => (a.ZScore ?? 0) - (b.ZScore ?? 0),
      render: (v) => (v != null ? v.toFixed(2) : '—'),
    },
    {
      title: 'Anomalies',
      key: 'anomalies',
      width: 180,
      render: (_, r) => (
        <Space size={2} wrap>
          {Object.keys(FLAG_LABELS)
            .filter((f) => r[f])
            .map((f) => (
              <Tag key={f} color={FLAG_COLORS[f]} style={{ fontSize: 10, padding: '0 4px' }}>
                {FLAG_LABELS[f]}
              </Tag>
            ))}
        </Space>
      ),
      filters: Object.keys(FLAG_LABELS).map((f) => ({ text: FLAG_LABELS[f], value: f })),
      onFilter: (v, r) => !!r[v],
    },
  ]
}

export default function SeasonsPage() {
  const [view, setView] = useState('devices')
  const [deviceData, setDeviceData] = useState([])
  const [userData, setUserData] = useState([])
  const [loading, setLoading] = useState(true)
  const [search, setSearch] = useState('')
  const { pipelineStatus, selectedEntity, setSelectedEntity } = useApp()
  const { onRow, contextMenuPortal, suppressModal } = useEntityContextMenu()

  useEffect(() => {
    setLoading(true)
    Promise.all([api.deviceSeasons(), api.userSeasons()]).then(([d, u]) => {
      setDeviceData(d.data?.data ?? [])
      setUserData(u.data?.data ?? [])
      setLoading(false)
    })
  }, [pipelineStatus.loaded_file])

  // Pre-populate search when navigated here from another module
  useEffect(() => {
    if (selectedEntity) {
      setSearch(selectedEntity.name)
      setView(selectedEntity.type === 'User' ? 'users' : 'devices')
      setSelectedEntity(null)
    }
  }, [selectedEntity, setSelectedEntity])

  const rows = view === 'devices' ? deviceData : userData
  const entityCol = view === 'devices' ? 'DeviceName' : 'AccountName'
  const columns = makeColumns(entityCol)

  const filtered = useMemo(() => {
    if (!search) return rows
    const q = search.toLowerCase()
    return rows.filter(
      (r) =>
        r[entityCol]?.toLowerCase().includes(q) ||
        r.TacticSet?.toLowerCase().includes(q),
    )
  }, [rows, search, entityCol])

  if (!loading && !pipelineStatus.is_loaded) return <EmptyState />

  return (
    <>
      {contextMenuPortal}
      {suppressModal}
      <Space style={{ marginBottom: 12 }}>
        <Radio.Group
          value={view}
          onChange={(e) => { setView(e.target.value); setSearch('') }}
          optionType="button"
          buttonStyle="solid"
          options={[
            { label: 'Devices', value: 'devices' },
            { label: 'Users', value: 'users' },
          ]}
        />
        <Input
          prefix={<SearchOutlined />}
          placeholder="Search entity or tactic…"
          value={search}
          onChange={(e) => setSearch(e.target.value)}
          allowClear
          style={{ width: 280 }}
        />
        <Typography.Text type="secondary" style={{ fontSize: 12 }}>
          {filtered.length} of {rows.length}
        </Typography.Text>
      </Space>
      <Table
        dataSource={filtered}
        columns={columns}
        rowKey={entityCol}
        loading={loading}
        size="small"
        pagination={{ pageSize: 50, showSizeChanger: true }}
        onRow={onRow}
        scroll={{ x: 1100 }}
      />
    </>
  )
}
