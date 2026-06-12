import React, { useEffect, useState } from 'react'
import { ArrowUpOutlined, RiseOutlined } from '@ant-design/icons'
import { Badge, Space, Spin, Table, Tag, Tooltip, Typography } from 'antd'
import { api } from '../api'
import EmptyState from '../components/EmptyState'
import { palette } from '../theme'

const { Text, Title } = Typography

function StatusTag({ status }) {
  if (status === 'Emerging') {
    return <Tag color="error" icon={<RiseOutlined />} style={{ fontWeight: 600 }}>Emerging</Tag>
  }
  if (status === 'Spreading') {
    return <Tag color="warning" icon={<ArrowUpOutlined />} style={{ fontWeight: 600 }}>Spreading</Tag>
  }
  return <Tag>{status}</Tag>
}

function scoreColor(v) {
  if (v >= 75) return palette.danger
  if (v >= 55) return palette.secondary
  return palette.amber
}

export default function OutbreaksPage() {
  const [data, setData] = useState(null)
  const [meta, setMeta] = useState({})
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState(null)

  useEffect(() => {
    api.outbreaks().then(({ data: d, error: e }) => {
      setLoading(false)
      if (e) { setError(e); return }
      setData(d.data || [])
      setMeta(d.meta || {})
      if (d.loaded === false) setData(null)
    })
  }, [])

  if (loading) return <Spin style={{ display: 'block', marginTop: 80 }} />
  if (error)   return <EmptyState message={`Failed to load outbreaks: ${error}`} />
  if (data === null) return <EmptyState message="No data loaded — run the pipeline first." />

  const columns = [
    {
      title: 'Detection Type',
      dataIndex: 'DetectionType',
      key: 'DetectionType',
      width: 230,
      render: (v, row) => (
        <Space direction="vertical" size={0}>
          <Text style={{ color: palette.text, fontSize: 13 }}>{v}</Text>
          {row.Tactic ? <Text type="secondary" style={{ fontSize: 11 }}>{row.Tactic}</Text> : null}
        </Space>
      ),
    },
    {
      title: 'Status',
      dataIndex: 'OutbreakStatus',
      key: 'OutbreakStatus',
      width: 130,
      filters: [
        { text: 'Emerging', value: 'Emerging' },
        { text: 'Spreading', value: 'Spreading' },
      ],
      onFilter: (val, row) => row.OutbreakStatus === val,
      render: (v) => <StatusTag status={v} />,
    },
    {
      title: 'Score',
      dataIndex: 'OutbreakScore',
      key: 'OutbreakScore',
      width: 90,
      align: 'right',
      defaultSortOrder: 'descend',
      sorter: (a, b) => a.OutbreakScore - b.OutbreakScore,
      render: (v) => <Text style={{ color: scoreColor(v), fontWeight: 600 }}>{v}</Text>,
    },
    {
      title: () => <Tooltip title="Detection severity (multiplier; floored at 2.0 for non-discountable types)">Severity</Tooltip>,
      dataIndex: 'Severity',
      key: 'Severity',
      width: 90,
      align: 'right',
      render: (v) => <Text type="secondary">{v}</Text>,
    },
    {
      title: () => <Tooltip title="Distinct devices firing this detection this run vs the previous run">Devices (now / prev)</Tooltip>,
      key: 'devices',
      width: 150,
      align: 'right',
      render: (_, row) => (
        <Text>
          <Text style={{ color: palette.text }}>{row.DeviceCountNow}</Text>
          <Text type="secondary"> / {row.DeviceCountPrev}</Text>
          {row.NewDevices > 0 ? <Text style={{ color: palette.success, fontSize: 11 }}> (+{row.NewDevices})</Text> : null}
        </Text>
      ),
    },
    {
      title: () => <Tooltip title="Least-squares slope of device count over recent runs (devices/run)">Slope</Tooltip>,
      dataIndex: 'SpreadSlope',
      key: 'SpreadSlope',
      width: 80,
      align: 'right',
      render: (v) => v > 0
        ? <Text style={{ color: palette.secondary }}>+{v}</Text>
        : <Text type="secondary">{v}</Text>,
    },
    {
      title: 'Runs seen',
      dataIndex: 'RunsSeenPrior',
      key: 'RunsSeenPrior',
      width: 90,
      align: 'right',
      render: (v) => <Text type="secondary">{v}</Text>,
    },
    {
      title: 'First seen',
      dataIndex: 'FirstSeen',
      key: 'FirstSeen',
      width: 130,
      render: (v) => <Text type="secondary" style={{ fontSize: 12 }}>{v ? String(v).slice(0, 10) : '—'}</Text>,
    },
  ]

  return (
    <Space direction="vertical" size={16} style={{ width: '100%' }}>
      <Title level={4} style={{ margin: 0, color: palette.text }}>Detection Outbreaks</Title>
      <Text type="secondary" style={{ maxWidth: 900 }}>
        Fleet-level epidemic curve: severe detections spreading device-to-device, individually sub-threshold
        on every host. This view names the detection, not the entity — pivot to{' '}
        <Text style={{ color: palette.primary }}>Slow Kill Chains</Text> or Seasons to find who.
      </Text>
      <Space size={24}>
        <Space><Badge status="error" /><Text type="secondary">Emerging: <Text style={{ color: palette.danger }}>{meta.emerging ?? 0}</Text></Text></Space>
        <Space><Badge status="warning" /><Text type="secondary">Spreading: <Text style={{ color: palette.amber }}>{meta.spreading ?? 0}</Text></Text></Space>
        <Text type="secondary" style={{ fontSize: 12 }}>{meta.total ?? 0} outbreak{(meta.total ?? 0) !== 1 ? 's' : ''}</Text>
      </Space>
      {(!data || data.length === 0) ? (
        <EmptyState message="No detection outbreaks (needs prior runs; endemic and benign detections stay silent)." />
      ) : (
        <Table
          dataSource={data}
          columns={columns}
          rowKey="DetectionType"
          size="small"
          pagination={false}
          scroll={{ x: 'max-content' }}
        />
      )}
    </Space>
  )
}
