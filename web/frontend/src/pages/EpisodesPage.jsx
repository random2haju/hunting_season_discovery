/**
 * Episode Timeline — vertical chronological list of episode cards per device.
 * Left panel: searchable device list.  Right panel: episode cards + scene table.
 */

import React, { useEffect, useState } from 'react'
import {
  Card, Col, Collapse, Empty, Input, List, Row, Space, Spin, Table, Tag, Typography,
} from 'antd'
import { SearchOutlined } from '@ant-design/icons'
import { api } from '../api'
import EmptyState from '../components/EmptyState'
import { useApp } from '../context/AppContext'

const { Text, Title } = Typography

const RISK_COLOR = (v) =>
  v >= 50 ? '#ff4d4f' : v >= 20 ? '#fa8c16' : v >= 5 ? '#faad14' : '#52c41a'

const SCENE_COLS = [
  { title: 'Timestamp', dataIndex: 'Timestamp', key: 'Timestamp', width: 160,
    render: (v) => v ? v.replace('T', ' ') : '—' },
  { title: 'Detection', dataIndex: 'DetectionType', key: 'DetectionType', ellipsis: true },
  { title: 'Tactic', dataIndex: 'TacticCategory', key: 'TacticCategory', width: 130 },
  { title: 'Score', dataIndex: 'ScoreContribution', key: 'ScoreContribution', width: 70,
    render: (v) => v?.toFixed(2) ?? '—' },
  { title: 'Evidence', dataIndex: 'Evidence', key: 'Evidence', ellipsis: true,
    render: (v) => <Text style={{ fontSize: 11 }}>{v}</Text> },
]

function EpisodeCard({ ep, scenes }) {
  const tactics = ep.Tactics?.split(', ').filter(Boolean) ?? []
  const families = ep.BehaviorFamilies?.split(', ').filter(Boolean) ?? []

  const epScenes = scenes.filter((s) => {
    if (!ep.StartTime || !ep.EndTime) return false
    const ts = s.Timestamp
    return ts >= ep.StartTime && ts <= ep.EndTime
  })

  return (
    <Collapse
      size="small"
      style={{ marginBottom: 8 }}
      items={[
        {
          key: '1',
          label: (
            <Space wrap>
              <Text strong style={{ color: RISK_COLOR(ep.EpisodeRiskScore ?? 0) }}>
                {ep.EpisodeRiskScore?.toFixed(1) ?? '—'}
              </Text>
              <Text type="secondary" style={{ fontSize: 11 }}>
                {ep.StartTime?.replace('T', ' ')} — {ep.DurationHours?.toFixed(1)}h
              </Text>
              <Text style={{ fontSize: 11 }}>{ep.SceneCount} scene{ep.SceneCount !== 1 ? 's' : ''}</Text>
              {tactics.map((t) => <Tag key={t} style={{ fontSize: 10 }}>{t}</Tag>)}
              {ep.AdaptiveBehaviorFlag && <Tag color="volcano">Adaptive</Tag>}
              {ep.TacticTransitions && <Tag color="purple">Transition</Tag>}
            </Space>
          ),
          children: (
            <Space direction="vertical" style={{ width: '100%' }} size={8}>
              {families.length > 0 && (
                <Space size={4}>
                  <Text type="secondary" style={{ fontSize: 11 }}>Families:</Text>
                  {families.map((f) => <Tag key={f} color="blue" style={{ fontSize: 10 }}>{f}</Tag>)}
                </Space>
              )}
              {ep.AdaptiveBehaviorReason && (
                <Text type="secondary" style={{ fontSize: 11 }}>
                  ⚡ {ep.AdaptiveBehaviorReason}
                </Text>
              )}
              <Table
                dataSource={epScenes.length ? epScenes : scenes.slice(0, 0)}
                columns={SCENE_COLS}
                rowKey={(r, i) => i}
                size="small"
                pagination={false}
                scroll={{ x: 700 }}
                locale={{ emptyText: 'No scenes matched this time window' }}
              />
            </Space>
          ),
        },
      ]}
    />
  )
}

export default function EpisodesPage() {
  const [allDevices, setAllDevices] = useState([])
  const [deviceSearch, setDeviceSearch] = useState('')
  const [selectedDevice, setSelectedDevice] = useState(null)
  const [detail, setDetail] = useState(null)
  const [loadingList, setLoadingList] = useState(true)
  const [loadingDetail, setLoadingDetail] = useState(false)
  const { pipelineStatus, selectedEntity, setSelectedEntity } = useApp()

  // Load unique device list from episode summaries
  useEffect(() => {
    setLoadingList(true)
    api.allEpisodes().then(({ data: d }) => {
      const devices = [...new Set((d?.data ?? []).map((r) => r.DeviceName))].sort()
      setAllDevices(devices)
      setLoadingList(false)
    })
  }, [pipelineStatus.loaded_file])

  // Cross-module navigation: auto-select device
  useEffect(() => {
    if (selectedEntity && selectedEntity.type !== 'User') {
      setSelectedDevice(selectedEntity.name)
      setSelectedEntity(null)
    }
  }, [selectedEntity, setSelectedEntity])

  useEffect(() => {
    if (!selectedDevice) return
    setLoadingDetail(true)
    api.deviceEpisodes(selectedDevice).then(({ data: d }) => {
      setDetail(d)
      setLoadingDetail(false)
    })
  }, [selectedDevice])

  if (!loadingList && !pipelineStatus.is_loaded) return <EmptyState />

  const filteredDevices = deviceSearch
    ? allDevices.filter((d) => d.toLowerCase().includes(deviceSearch.toLowerCase()))
    : allDevices

  return (
    <Row gutter={16} style={{ height: 'calc(100vh - 120px)' }}>
      {/* Device list */}
      <Col flex="220px" style={{ height: '100%', overflowY: 'auto' }}>
        <Input
          prefix={<SearchOutlined />}
          placeholder="Filter devices…"
          value={deviceSearch}
          onChange={(e) => setDeviceSearch(e.target.value)}
          allowClear
          size="small"
          style={{ marginBottom: 8 }}
        />
        {loadingList ? (
          <Spin size="small" />
        ) : (
          <List
            size="small"
            dataSource={filteredDevices}
            renderItem={(d) => (
              <List.Item
                style={{
                  cursor: 'pointer',
                  padding: '6px 8px',
                  background: d === selectedDevice ? '#1677ff22' : 'transparent',
                  borderRadius: 4,
                }}
                onClick={() => setSelectedDevice(d)}
              >
                <Text code style={{ fontSize: 11 }}>{d}</Text>
              </List.Item>
            )}
          />
        )}
      </Col>

      {/* Episode timeline */}
      <Col flex="1" style={{ height: '100%', overflowY: 'auto' }}>
        {!selectedDevice ? (
          <Empty description="Select a device to view its episodes" />
        ) : loadingDetail ? (
          <Spin />
        ) : !detail || detail.episodes.length === 0 ? (
          <Empty description={`No episodes found for ${selectedDevice}`} />
        ) : (
          <>
            <Title level={5} style={{ marginBottom: 12 }}>
              {selectedDevice} — {detail.episodes.length} episode{detail.episodes.length !== 1 ? 's' : ''}
            </Title>
            {detail.episodes.map((ep, i) => (
              <EpisodeCard key={i} ep={ep} scenes={detail.scenes ?? []} />
            ))}
          </>
        )}
      </Col>
    </Row>
  )
}
