import React, { useCallback, useEffect, useMemo, useState } from 'react'
import { Input, Radio, Select, Space, Table, Tag, Tooltip, Typography } from 'antd'
import { SearchOutlined } from '@ant-design/icons'
import { api } from '../api'
import { ColHeader } from '../components/ColHeader'
import EmptyState from '../components/EmptyState'
import { useEntityContextMenu } from '../components/EntityContextMenu'
import { useEntityDetailDrawer } from '../components/EntityDetailDrawer'
import { useApp } from '../context/AppContext'
import { riskColor as RISK_COLOR } from '../theme'

const { Text } = Typography

const FLAG_LABELS = {
  IsScoreSpike: 'Spike', IsNewHigh: 'NewHigh',
  IsTacticExpansion: 'TacticExp', IsAdaptingTactics: 'Adapting', IsEmergingEntity: 'Emerging',
}
const FLAG_COLORS = {
  IsScoreSpike: 'red', IsNewHigh: 'orange',
  IsTacticExpansion: 'purple', IsAdaptingTactics: 'magenta', IsEmergingEntity: 'cyan',
}

function makeColumns(entityCol) {
  const entityLabel = entityCol === 'DeviceName' ? 'Device hostname' : 'User account name'
  return [
    {
      title: <ColHeader label="Entity" tip={`${entityLabel} observed in detections.`} />,
      dataIndex: entityCol,
      key: entityCol,
      ellipsis: true,
      render: (v) => <Text code style={{ fontSize: 12 }}>{v}</Text>,
    },
    {
      title: <ColHeader label="Risk" tip="TotalRisk — weighted sum of episode scores using diminishing returns by episode rank and repeated behavior family." />,
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
      title: <ColHeader label="Tactics" tip="Number of distinct MITRE ATT&CK tactics observed across all episodes. Higher counts indicate broader attack coverage." />,
      dataIndex: 'UniqueTactics',
      key: 'UniqueTactics',
      width: 70,
      sorter: (a, b) => (a.UniqueTactics ?? 0) - (b.UniqueTactics ?? 0),
    },
    {
      title: <ColHeader label="Tactic Set" tip="Full list of MITRE ATT&CK tactics seen across all episodes for this entity, sorted alphabetically." />,
      dataIndex: 'TacticSet',
      key: 'TacticSet',
      ellipsis: true,
      render: (v) => <Tooltip title={v}><Text style={{ fontSize: 11 }}>{v}</Text></Tooltip>,
    },
    {
      title: <ColHeader label="Workflow" tip="Primary workflow classification: Operational (standard endpoint), AIWorkflow (AI agent activity), DeveloperAutomation (IDE/dev tooling), ServiceAutomation (service/machine account). Automation entities need ≥2 tactics to reach Priority Cases, unless they have a high TotalRisk or a non-discountable detection." />,
      dataIndex: 'PrimaryWorkflowClass',
      key: 'PrimaryWorkflowClass',
      width: 140,
      filters: [
        { text: 'Operational', value: 'Operational' },
        { text: 'AIWorkflow', value: 'AIWorkflow' },
        { text: 'DeveloperAutomation', value: 'DeveloperAutomation' },
        { text: 'ServiceAutomation', value: 'ServiceAutomation' },
      ],
      onFilter: (v, r) => r.PrimaryWorkflowClass === v,
    },
    {
      title: <ColHeader label="Eligible" tip="Whether this entity qualifies for Priority Cases. AI/Dev-workflow entities are excluded unless they span ≥2 distinct MITRE tactics." />,
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
      title: <ColHeader label="Suppressed" tip="Analyst-suppressed entities are hidden from Priority Cases. Hover the tag to see the suppression reason." />,
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
      title: <ColHeader label="Episodes" tip="Number of detection episodes — clusters of scenes on the same entity within a 4-hour sliding window." />,
      dataIndex: 'EpisodeCount',
      key: 'EpisodeCount',
      width: 80,
      sorter: (a, b) => (a.EpisodeCount ?? 0) - (b.EpisodeCount ?? 0),
    },
    {
      title: <ColHeader label="Z-Score" tip="Standard deviations above this entity's historical mean score. Values ≥2 are unusual; requires at least 3 prior runs to be meaningful." />,
      dataIndex: 'ZScore',
      key: 'ZScore',
      width: 75,
      sorter: (a, b) => (a.ZScore ?? 0) - (b.ZScore ?? 0),
      render: (v) => (v != null ? v.toFixed(2) : '—'),
    },
    {
      title: <ColHeader label="Anomalies" tip="Historical anomaly flags: Spike = score >2.5× baseline mean; NewHigh = all-time high; TacticExp = more tactics than ever before; Adapting = new tactic not seen in prior runs; Emerging = new entity with elevated score." />,
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
  const [tacticFilter, setTacticFilter] = useState([])
  const [familyFilter, setFamilyFilter] = useState([])
  const { pipelineStatus, selectedEntity, setSelectedEntity } = useApp()
  const { openDetail, entityDetailDrawer } = useEntityDetailDrawer()
  const { onRow, contextMenuPortal, suppressModal, triageModal } = useEntityContextMenu({ onViewDetails: openDetail })

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

  const allTactics = useMemo(() => {
    const set = new Set()
    rows.forEach((r) => {
      if (r.TacticSet) r.TacticSet.split(',').forEach((t) => { const s = t.trim(); if (s) set.add(s) })
    })
    return [...set].sort()
  }, [rows])

  const allFamilies = useMemo(() => {
    const set = new Set()
    rows.forEach((r) => {
      if (r.BehaviorFamilies) r.BehaviorFamilies.split(',').forEach((f) => { const s = f.trim(); if (s) set.add(s) })
    })
    return [...set].sort()
  }, [rows])

  const filtered = useMemo(() => {
    let result = rows
    if (search) {
      const q = search.toLowerCase()
      result = result.filter(
        (r) =>
          r[entityCol]?.toLowerCase().includes(q) ||
          r.TacticSet?.toLowerCase().includes(q) ||
          r.BehaviorFamilies?.toLowerCase().includes(q),
      )
    }
    if (tacticFilter.length > 0) {
      result = result.filter((r) => {
        const tactics = (r.TacticSet ?? '').split(',').map((t) => t.trim())
        return tacticFilter.every((t) => tactics.includes(t))
      })
    }
    if (familyFilter.length > 0) {
      result = result.filter((r) => {
        const families = (r.BehaviorFamilies ?? '').split(',').map((f) => f.trim())
        return familyFilter.every((f) => families.includes(f))
      })
    }
    return result
  }, [rows, search, entityCol, tacticFilter, familyFilter])

  if (!loading && !pipelineStatus.is_loaded) return <EmptyState />

  return (
    <>
      {contextMenuPortal}
      {suppressModal}
      {triageModal}
      {entityDetailDrawer}
      <Space style={{ marginBottom: 12 }} wrap>
        <Radio.Group
          value={view}
          onChange={(e) => { setView(e.target.value); setSearch(''); setTacticFilter([]); setFamilyFilter([]) }}
          optionType="button"
          buttonStyle="solid"
          options={[
            { label: 'Devices', value: 'devices' },
            { label: 'Users', value: 'users' },
          ]}
        />
        <Input
          prefix={<SearchOutlined />}
          placeholder="Search entity, tactic or family…"
          value={search}
          onChange={(e) => setSearch(e.target.value)}
          allowClear
          style={{ width: 260 }}
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
        <Select
          mode="multiple"
          allowClear
          placeholder="Filter by behavior family…"
          value={familyFilter}
          onChange={setFamilyFilter}
          options={allFamilies.map((f) => ({ label: f, value: f }))}
          style={{ minWidth: 220 }}
          maxTagCount={2}
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
        onRow={tableOnRow}
        scroll={{ x: 1100 }}
      />
    </>
  )
}
