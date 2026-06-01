/**
 * Stacking Analysis — table + bar chart side by side.
 * Toggle between all detections and AI-family only.
 * Sorted rarest-first (lowest EnvDeviceCount).
 */

import React, { useEffect, useMemo, useState } from 'react'
import { Col, Radio, Row, Space, Table, Tooltip, Typography } from 'antd'
import createPlotlyComponent from 'react-plotly.js/factory'
import Plotly from 'plotly.js-dist-min'
import { api } from '../api'
import EmptyState from '../components/EmptyState'
import { useApp } from '../context/AppContext'

const Plot = createPlotlyComponent(Plotly)
const { Text } = Typography

const TABLE_COLS = [
  {
    title: 'Tactic',
    dataIndex: 'TacticCategory',
    key: 'TacticCategory',
    width: 110,
    filters: [],
    onFilter: (v, r) => r.TacticCategory === v,
  },
  {
    title: 'Detection',
    dataIndex: 'DetectionType',
    key: 'DetectionType',
    ellipsis: true,
    width: 180,
  },
  {
    title: 'Evidence',
    dataIndex: 'Evidence',
    key: 'Evidence',
    ellipsis: true,
    render: (v) => <Tooltip title={v}><Text style={{ fontSize: 11 }}>{v}</Text></Tooltip>,
  },
  {
    title: 'Devices',
    dataIndex: 'EnvDeviceCount',
    key: 'EnvDeviceCount',
    width: 75,
    sorter: (a, b) => (a.EnvDeviceCount ?? 0) - (b.EnvDeviceCount ?? 0),
    defaultSortOrder: 'ascend',
  },
  {
    title: 'Accounts',
    dataIndex: 'UniqueAccounts',
    key: 'UniqueAccounts',
    width: 85,
    sorter: (a, b) => (a.UniqueAccounts ?? 0) - (b.UniqueAccounts ?? 0),
  },
  {
    title: 'Hits',
    dataIndex: 'TotalHits',
    key: 'TotalHits',
    width: 65,
    sorter: (a, b) => (a.TotalHits ?? 0) - (b.TotalHits ?? 0),
  },
  {
    title: 'Prev',
    dataIndex: 'PrevalenceMultiplier',
    key: 'PrevalenceMultiplier',
    width: 60,
    render: (v) => {
      if (v == null) return '—'
      const color = v < 1 ? '#ff4d4f' : v > 1 ? '#52c41a' : '#d9d9d9'
      return <Text style={{ color }}>{v}×</Text>
    },
  },
]

export default function StackingPage() {
  const [family, setFamily] = useState('all')
  const [data, setData] = useState([])
  const [loading, setLoading] = useState(true)
  const { pipelineStatus } = useApp()

  useEffect(() => {
    setLoading(true)
    api.stacking(family).then(({ data: d }) => {
      setData(d?.data ?? [])
      setLoading(false)
    })
  }, [family, pipelineStatus.loaded_file])

  if (!loading && !pipelineStatus.is_loaded) return <EmptyState />

  // Top 30 rarest patterns for the chart (sorted ascending = rarest first)
  const chartData = useMemo(() => {
    const sorted = [...data].sort((a, b) => (a.EnvDeviceCount ?? 0) - (b.EnvDeviceCount ?? 0))
    const top = sorted.slice(0, 30)
    return {
      labels: top.map((r) => r.Evidence?.slice(0, 60) ?? ''),
      devices: top.map((r) => r.EnvDeviceCount ?? 0),
      colors: top.map((r) =>
        (r.PrevalenceMultiplier ?? 1) > 1 ? '#52c41a' :
        (r.PrevalenceMultiplier ?? 1) < 1 ? '#ff4d4f' : '#1677ff'
      ),
    }
  }, [data])

  const traces = [
    {
      type: 'bar',
      orientation: 'h',
      x: chartData.devices,
      y: chartData.labels,
      marker: { color: chartData.colors },
      name: 'Device count',
    },
  ]

  const layout = {
    paper_bgcolor: 'transparent',
    plot_bgcolor: 'transparent',
    font: { color: '#d9d9d9', size: 11 },
    xaxis: { gridcolor: '#2a2a2a', title: 'Devices (rarest first ←)' },
    yaxis: { automargin: true, tickfont: { size: 10 } },
    margin: { t: 10, r: 20, b: 40, l: 10 },
    height: Math.max(300, chartData.labels.length * 22),
  }

  return (
    <div>
      <Space style={{ marginBottom: 12 }}>
        <Radio.Group
          value={family}
          onChange={(e) => setFamily(e.target.value)}
          optionType="button"
          buttonStyle="solid"
          options={[
            { label: 'All detections', value: 'all' },
            { label: 'AI family', value: 'ai' },
          ]}
        />
        <Text type="secondary" style={{ fontSize: 12 }}>
          {data.length} pattern{data.length !== 1 ? 's' : ''}
        </Text>
      </Space>

      <Row gutter={16}>
        <Col span={12}>
          <Table
            dataSource={data}
            columns={TABLE_COLS}
            rowKey={(r, i) => i}
            loading={loading}
            size="small"
            pagination={{ pageSize: 30, showSizeChanger: false }}
            scroll={{ x: 700, y: 600 }}
          />
        </Col>
        <Col span={12} style={{ overflowY: 'auto', maxHeight: 700 }}>
          {data.length > 0 && (
            <Plot
              data={traces}
              layout={layout}
              config={{ responsive: true, displayModeBar: false }}
              style={{ width: '100%' }}
            />
          )}
        </Col>
      </Row>
    </div>
  )
}
