import React, { useEffect, useState } from 'react'
import { AimOutlined } from '@ant-design/icons'
import { Alert, Badge, Card, Space, Spin, Table, Tag, Tooltip, Typography } from 'antd'
import { api } from '../api'
import EmptyState from '../components/EmptyState'
import { palette } from '../theme'

const { Text, Title, Paragraph } = Typography

function StatusTag({ status }) {
  if (status === 'Emerging')  return <Tag color="error">{status}</Tag>
  if (status === 'Spreading') return <Tag color="warning">{status}</Tag>
  return <Tag>{status}</Tag>
}

function scoreColor(v) {
  if (v >= 75) return palette.danger
  if (v >= 55) return palette.secondary
  return palette.amber
}

export default function CampaignsPage() {
  const [data, setData] = useState(null)
  const [meta, setMeta] = useState({})
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState(null)

  useEffect(() => {
    api.campaigns().then(({ data: d, error: e }) => {
      setLoading(false)
      if (e) { setError(e); return }
      setData(d.data || [])
      setMeta(d.meta || {})
      if (d.loaded === false) setData(null)
    })
  }, [])

  if (loading) return <Spin style={{ display: 'block', marginTop: 80 }} />
  if (error)   return <EmptyState message={`Failed to load campaigns: ${error}`} />
  if (data === null) return <EmptyState message="No data loaded — run the pipeline first." />

  const columns = [
    {
      title: 'Detection (pathogen)',
      dataIndex: 'DetectionType',
      key: 'DetectionType',
      width: 210,
      render: (v, row) => (
        <Space direction="vertical" size={0}>
          <Text style={{ color: palette.text, fontSize: 13, fontWeight: 600 }}>{v}</Text>
          <Text type="secondary" style={{ fontSize: 11 }}>via {row.Tactic}</Text>
        </Space>
      ),
    },
    {
      title: () => <Tooltip title="Population signal + per-chain corroboration + breadth of linked entities">Campaign score</Tooltip>,
      dataIndex: 'CampaignScore',
      key: 'CampaignScore',
      width: 130,
      align: 'right',
      defaultSortOrder: 'descend',
      sorter: (a, b) => a.CampaignScore - b.CampaignScore,
      render: (v) => <Text style={{ color: scoreColor(v), fontWeight: 700, fontSize: 15 }}>{v}</Text>,
    },
    {
      title: 'Outbreak',
      key: 'outbreak',
      width: 150,
      render: (_, row) => (
        <Space size={6}>
          <StatusTag status={row.OutbreakStatus} />
          <Text type="secondary" style={{ fontSize: 12 }}>{row.DeviceCountNow} dev</Text>
        </Space>
      ),
    },
    {
      title: () => <Tooltip title="Distinct slow-chain entities whose progression includes this tactic">Linked chains</Tooltip>,
      key: 'linked',
      width: 150,
      align: 'right',
      render: (_, row) => (
        <Text>
          <Text style={{ color: palette.text, fontWeight: 600 }}>{row.LinkedEntityCount}</Text>
          <Text type="secondary" style={{ fontSize: 11 }}>
            {' '}({row.StagingChains} staging, {row.CompleteChains} complete)
          </Text>
        </Text>
      ),
    },
    {
      title: 'Entities',
      dataIndex: 'LinkedEntities',
      key: 'LinkedEntities',
      render: (v) => <Text type="secondary" style={{ fontSize: 12 }}>{v}</Text>,
    },
  ]

  return (
    <Space direction="vertical" size={16} style={{ width: '100%' }}>
      <Space align="center" size={10}>
        <AimOutlined style={{ color: palette.danger, fontSize: 20 }} />
        <Title level={4} style={{ margin: 0, color: palette.text }}>Campaigns</Title>
      </Space>
      <Paragraph type="secondary" style={{ maxWidth: 920, marginBottom: 0 }}>
        The cross-layer overlay — the strongest signal in the pipeline. A campaign fires when one detection
        is <b>both</b> climbing the fleet&apos;s epidemic curve (an outbreak) <b>and</b> threaded through several
        entities&apos; slow kill chains. Either alone is ambiguous; their intersection is the Broad Street pump
        moment — a common source no sporadic coincidence can explain.
      </Paragraph>

      {data && data.length > 0 && (
        <Alert
          type="error"
          showIcon
          message={`${meta.total} active campaign${meta.total !== 1 ? 's' : ''} — ${meta.linked_entities} linked chain entit${meta.linked_entities !== 1 ? 'ies' : 'y'}`}
          description="Each row is a detection both spreading across the fleet and assembling kill chains on multiple hosts. Pivot to Slow Kill Chains for the per-entity progressions."
          style={{ background: 'rgba(255,77,77,0.08)', border: `1px solid ${palette.danger}` }}
        />
      )}

      {(!data || data.length === 0) ? (
        <EmptyState message="No cross-layer campaigns — needs an active outbreak whose tactic threads ≥2 slow chains." />
      ) : (
        <Space direction="vertical" size={16} style={{ width: '100%' }}>
          <Table
            dataSource={data}
            columns={columns}
            rowKey={(r) => `${r.DetectionType}|${r.Tactic}`}
            size="small"
            pagination={false}
            scroll={{ x: 'max-content' }}
            expandable={{
              expandedRowRender: (row) => (
                <Text style={{ color: palette.muted, fontSize: 12 }}>{row.Rationale}</Text>
              ),
              rowExpandable: (row) => !!row.Rationale,
            }}
          />
        </Space>
      )}
    </Space>
  )
}
