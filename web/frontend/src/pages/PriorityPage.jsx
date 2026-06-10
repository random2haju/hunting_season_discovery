import React, { useCallback, useEffect, useMemo, useState } from 'react'
import { Input, Select, Space, Table, Tag, Tooltip, Typography } from 'antd'
import { SearchOutlined } from '@ant-design/icons'
import { api } from '../api'
import { ColHeader } from '../components/ColHeader'
import EmptyState from '../components/EmptyState'
import { useEntityContextMenu } from '../components/EntityContextMenu'
import { useEntityDetailDrawer } from '../components/EntityDetailDrawer'
import { TriagePicker, TRIAGE_STATUSES } from '../components/TriageControls'
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
    title: <ColHeader label="Type" tip="Whether this entity is a Device (hostname) or User (account name)." />,
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
    title: <ColHeader label="Entity" tip="Device hostname or user account name observed in detections." />,
    dataIndex: 'EntityName',
    key: 'EntityName',
    ellipsis: true,
    render: (v) => <Text code style={{ fontSize: 12 }}>{v}</Text>,
  },
  {
    title: <ColHeader label="Score" tip="Composite ranking score = TotalRisk + HistoricalPriority × weight. Used to order this list — hover a cell to see the breakdown." />,
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
    title: <ColHeader label="Risk" tip="TotalRisk — weighted sum of episode scores using diminishing returns by episode rank and repeated behavior family." />,
    dataIndex: 'TotalRisk',
    key: 'TotalRisk',
    width: 75,
    sorter: (a, b) => (a.TotalRisk ?? 0) - (b.TotalRisk ?? 0),
    render: (v) => <Text style={{ fontSize: 11, color: RISK_COLOR(v ?? 0) }}>{v?.toFixed(1) ?? '—'}</Text>,
  },
  {
    title: <ColHeader label="HP" tip="Historical Priority — anomaly bonus derived from Z-score and anomaly flags (Spike, NewHigh, TacticExp, Adapting, Emerging). Surfaces entities that changed significantly vs their baseline." />,
    dataIndex: 'HistoricalPriority',
    key: 'HistoricalPriority',
    width: 60,
    sorter: (a, b) => (a.HistoricalPriority ?? 0) - (b.HistoricalPriority ?? 0),
    render: (v) => v != null && v > 0
      ? <Text style={{ fontSize: 11, color: palette.primary }}>{v.toFixed(1)}</Text>
      : <Text type="secondary" style={{ fontSize: 11 }}>—</Text>,
  },
  {
    title: <ColHeader label="Pct" tip="Risk percentile — how this entity ranks relative to all entities in the current run (100% = highest risk)." />,
    dataIndex: 'RiskPercentile',
    key: 'RiskPercentile',
    width: 55,
    render: (v) => (v != null ? `${v}%` : '—'),
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
    width: 120,
    filters: [
      { text: 'Operational', value: 'Operational' },
      { text: 'AIWorkflow', value: 'AIWorkflow' },
      { text: 'DeveloperAutomation', value: 'DeveloperAutomation' },
      { text: 'ServiceAutomation', value: 'ServiceAutomation' },
    ],
    onFilter: (v, r) => r.PrimaryWorkflowClass === v,
  },
  {
    title: <ColHeader label="AI%" tip="Percentage of detection scenes classified as AI agent activity (e.g. Claude, Copilot, local LLM). 0% = no AI context; high % = most activity is AI-generated." />,
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
    title: <ColHeader label="Episodes" tip="Number of detection episodes — clusters of scenes on the same entity within a 4-hour sliding window." />,
    dataIndex: 'EpisodeCount',
    key: 'EpisodeCount',
    width: 80,
    sorter: (a, b) => (a.EpisodeCount ?? 0) - (b.EpisodeCount ?? 0),
  },
  {
    title: <ColHeader label="Anomalies" tip="Historical anomaly flags: Spike = score >2.5× baseline mean; NewHigh = all-time high; TacticExp = more tactics than ever before; Adapting = new tactic not seen in prior runs; Emerging = new entity with elevated score." />,
    key: 'anomalies',
    width: 200,
    render: (_, r) => <AnomalyFlags record={r} />,
    filters: Object.keys(FLAG_COLORS).map((f) => ({ text: FLAG_LABELS[f], value: f })),
    onFilter: (v, r) => !!r[v],
  },
]

// Default status filter hides Benign — dispositioned cases leave the queue,
// one click on the Benign chip brings them back.
const DEFAULT_STATUS_FILTER = TRIAGE_STATUSES.filter((s) => s !== 'Benign')

export default function PriorityPage() {
  const [data, setData] = useState([])
  const [loading, setLoading] = useState(true)
  const [search, setSearch] = useState('')
  const [tacticFilter, setTacticFilter] = useState([])
  const [familyFilter, setFamilyFilter] = useState([])
  const [statusFilter, setStatusFilter] = useState(DEFAULT_STATUS_FILTER)
  const { pipelineStatus } = useApp()

  const load = useCallback(() => {
    setLoading(true)
    api.priorityCases().then(({ data: d }) => {
      setData(d?.data ?? [])
      setLoading(false)
    })
  }, [])

  const { openDetail, entityDetailDrawer } = useEntityDetailDrawer({ onTriageChanged: load })
  const { onRow, contextMenuPortal, suppressModal, triageModal, openTriage } =
    useEntityContextMenu({ onViewDetails: openDetail, onTriageChanged: load })

  const tableOnRow = useCallback(
    (record) => ({
      ...onRow(record),
      onClick: () => openDetail(record),
      style: { cursor: 'pointer' },
    }),
    [onRow, openDetail],
  )

  useEffect(() => {
    load()
  }, [pipelineStatus.loaded_file, load])

  const columns = useMemo(() => {
    const statusCol = {
      title: (
        <ColHeader
          label="Status"
          tip="Analyst triage state. New = untriaged; Investigating = claimed; Benign / Escalated = verdicts (note required); Reopened = was Benign but newer activity arrived. ● = new activity since triage; clock = stale investigation. Click to change."
        />
      ),
      dataIndex: 'TriageStatus',
      key: 'TriageStatus',
      width: 110,
      render: (_, r) => <TriagePicker record={r} openTriage={openTriage} />,
    }
    const cols = [...COLUMNS]
    cols.splice(2, 0, statusCol)
    return cols
  }, [openTriage])

  const statusCounts = useMemo(() => {
    const counts = {}
    TRIAGE_STATUSES.forEach((s) => { counts[s] = 0 })
    data.forEach((r) => {
      const s = r.TriageStatus ?? 'New'
      counts[s] = (counts[s] ?? 0) + 1
    })
    return counts
  }, [data])

  const allTactics = useMemo(() => {
    const set = new Set()
    data.forEach((r) => {
      if (r.TacticSet) r.TacticSet.split(',').forEach((t) => { const s = t.trim(); if (s) set.add(s) })
    })
    return [...set].sort()
  }, [data])

  const allFamilies = useMemo(() => {
    const set = new Set()
    data.forEach((r) => {
      if (r.BehaviorFamilies) r.BehaviorFamilies.split(',').forEach((f) => { const s = f.trim(); if (s) set.add(s) })
    })
    return [...set].sort()
  }, [data])

  const filtered = useMemo(() => {
    let result = data
    if (statusFilter.length < TRIAGE_STATUSES.length) {
      result = result.filter((r) => statusFilter.includes(r.TriageStatus ?? 'New'))
    }
    if (search) {
      const q = search.toLowerCase()
      result = result.filter(
        (r) =>
          r.EntityName?.toLowerCase().includes(q) ||
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
  }, [data, search, tacticFilter, familyFilter, statusFilter])

  if (!loading && !pipelineStatus.is_loaded) return <EmptyState />

  return (
    <>
      {contextMenuPortal}
      {suppressModal}
      {triageModal}
      {entityDetailDrawer}
      <Space style={{ marginBottom: 12 }} wrap>
        <Space size={2}>
          {TRIAGE_STATUSES.map((s) => (
            <Tag.CheckableTag
              key={s}
              checked={statusFilter.includes(s)}
              onChange={(checked) =>
                setStatusFilter((f) => (checked ? [...f, s] : f.filter((x) => x !== s)))
              }
              style={{ fontSize: 11, border: `1px solid ${palette.border}` }}
            >
              {s} {statusCounts[s] ?? 0}
            </Tag.CheckableTag>
          ))}
        </Space>
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
        <Text type="secondary" style={{ fontSize: 12 }}>
          {filtered.length} case{filtered.length !== 1 ? 's' : ''}
          {(search || tacticFilter.length > 0 || familyFilter.length > 0
            || statusFilter.length < TRIAGE_STATUSES.length) ? ` (filtered from ${data.length})` : ''}
        </Text>
      </Space>
      <Table
        dataSource={filtered}
        columns={columns}
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
