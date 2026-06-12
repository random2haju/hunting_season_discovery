import React, { useEffect, useState } from 'react'
import { Badge, Space, Spin, Table, Tag, Tooltip, Typography } from 'antd'
import { useNavigate } from 'react-router-dom'
import { api } from '../api'
import EmptyState from '../components/EmptyState'
import { palette } from '../theme'

const { Text, Title } = Typography

function StatusTag({ status }) {
  // Staging (collected, not yet exfiltrated) is the actionable pre-exfil alarm.
  if (status === 'Staging') {
    return <Tag color="warning" style={{ fontWeight: 600 }}>Staging</Tag>
  }
  if (status === 'Complete') {
    return <Tag color="error" style={{ fontWeight: 600 }}>Complete</Tag>
  }
  return <Tag>{status}</Tag>
}

function confColor(v) {
  if (v >= 75) return palette.danger
  if (v >= 55) return palette.secondary
  return palette.amber
}

export default function SlowChainsPage() {
  const [data, setData] = useState(null)
  const [meta, setMeta] = useState({})
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState(null)
  const navigate = useNavigate()

  useEffect(() => {
    api.slowChains().then(({ data: d, error: e }) => {
      setLoading(false)
      if (e) { setError(e); return }
      setData(d.data || [])
      setMeta(d.meta || {})
      if (d.loaded === false) setData(null)
    })
  }, [])

  if (loading) return <Spin style={{ display: 'block', marginTop: 80 }} />
  if (error)   return <EmptyState message={`Failed to load slow kill chains: ${error}`} />
  if (data === null) return <EmptyState message="No data loaded — run the pipeline first." />

  function goToEntity(row) {
    const type = row.EntityType
    const name = row.EntityName
    if (type === 'Device') navigate(`/episodes?entity=${encodeURIComponent(name)}&type=Device`)
    else navigate(`/episodes?entity=${encodeURIComponent(name)}&type=User`)
  }

  const columns = [
    {
      title: 'Entity',
      dataIndex: 'EntityName',
      key: 'EntityName',
      width: 200,
      render: (v, row) => (
        <Space direction="vertical" size={0}>
          <Typography.Link onClick={() => goToEntity(row)} style={{ fontSize: 13 }}>{v}</Typography.Link>
          <Text type="secondary" style={{ fontSize: 11 }}>{row.EntityType}</Text>
        </Space>
      ),
    },
    {
      title: 'Status',
      dataIndex: 'ChainStatus',
      key: 'ChainStatus',
      width: 110,
      filters: [
        { text: 'Staging', value: 'Staging' },
        { text: 'Complete', value: 'Complete' },
      ],
      onFilter: (val, row) => row.ChainStatus === val,
      render: (v) => <StatusTag status={v} />,
    },
    {
      title: 'Confidence',
      dataIndex: 'ChainConfidence',
      key: 'ChainConfidence',
      width: 110,
      align: 'right',
      defaultSortOrder: 'descend',
      sorter: (a, b) => a.ChainConfidence - b.ChainConfidence,
      render: (v) => <Text style={{ color: confColor(v), fontWeight: 600 }}>{v}</Text>,
    },
    {
      title: 'Chain',
      dataIndex: 'ChainName',
      key: 'ChainName',
      width: 230,
      render: (v) => <Tag style={{ borderColor: palette.border, color: palette.muted, background: 'transparent' }}>{v}</Tag>,
    },
    {
      title: 'Reached',
      dataIndex: 'StagesReached',
      key: 'StagesReached',
      width: 240,
      render: (v) => <Text style={{ fontSize: 12 }}>{v}</Text>,
    },
    {
      title: () => (
        <Tooltip title="The unmatched final stage — for Staging rows, what has NOT happened yet (the window to act)">Missing</Tooltip>
      ),
      dataIndex: 'MissingStage',
      key: 'MissingStage',
      width: 130,
      render: (v) => v ? <Tag color="warning">{v}</Tag> : <Text type="secondary">—</Text>,
    },
    {
      title: () => (
        <Tooltip title="A counterpart (account/device) common to every run in the chain — strong corroboration">Shared thread</Tooltip>
      ),
      dataIndex: 'SharedThread',
      key: 'SharedThread',
      width: 150,
      render: (v) => v ? <Text style={{ color: palette.primary, fontSize: 12 }}>{v}</Text> : <Text type="secondary">—</Text>,
    },
    {
      title: 'Runs',
      dataIndex: 'RunsSpanned',
      key: 'RunsSpanned',
      width: 70,
      align: 'right',
      render: (v) => <Text type="secondary">{v}</Text>,
    },
    {
      title: 'Span (d)',
      dataIndex: 'SpanDays',
      key: 'SpanDays',
      width: 80,
      align: 'right',
      render: (v) => <Text type="secondary">{v}</Text>,
    },
    {
      title: 'Timeline',
      dataIndex: 'MatchedTimeline',
      key: 'MatchedTimeline',
      render: (v) => <Text type="secondary" style={{ fontSize: 11 }}>{v}</Text>,
    },
  ]

  return (
    <Space direction="vertical" size={16} style={{ width: '100%' }}>
      <Title level={4} style={{ margin: 0, color: palette.text }}>Slow Kill Chains</Title>
      <Text type="secondary" style={{ maxWidth: 900 }}>
        Tactic progressions assembled across multiple hunt runs — the low-and-slow espionage signal no
        single run can see. <Text style={{ color: palette.amber }}>Staging</Text> means data was collected
        but not yet exfiltrated: the window to act.
      </Text>
      <Space size={24}>
        <Space><Badge status="warning" /><Text type="secondary">Staging: <Text style={{ color: palette.amber }}>{meta.staging ?? 0}</Text></Text></Space>
        <Space><Badge status="error" /><Text type="secondary">Complete: <Text style={{ color: palette.danger }}>{meta.complete ?? 0}</Text></Text></Space>
        <Text type="secondary" style={{ fontSize: 12 }}>{meta.total ?? 0} chain{(meta.total ?? 0) !== 1 ? 's' : ''}</Text>
      </Space>
      {(!data || data.length === 0) ? (
        <EmptyState message="No cross-run slow chains detected (needs ≥2 runs of history to assemble)." />
      ) : (
        <Table
          dataSource={data}
          columns={columns}
          rowKey={(r) => `${r.EntityType}|${r.EntityName}|${r.ChainName}`}
          size="small"
          pagination={false}
          scroll={{ x: 'max-content' }}
        />
      )}
    </Space>
  )
}
