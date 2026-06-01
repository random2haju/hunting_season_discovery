/**
 * Historical Trends — line chart of TotalRisk per entity over calendar runs.
 * Anomaly flags appear as colored markers on the line.
 */

import React, { useEffect, useMemo, useState } from 'react'
import { AutoComplete, Card, Col, Empty, Row, Select, Space, Spin, Tag, Typography } from 'antd'
import createPlotlyComponent from 'react-plotly.js/factory'
import Plotly from 'plotly.js-dist-min'
import { api } from '../api'
import EmptyState from '../components/EmptyState'
import { useApp } from '../context/AppContext'

const Plot = createPlotlyComponent(Plotly)
const { Text, Title } = Typography

const ANOMALY_MARKERS = {
  IsScoreSpike:     { color: '#ff4d4f', symbol: 'star',     label: 'Spike' },
  IsNewHigh:        { color: '#fa8c16', symbol: 'triangle-up', label: 'NewHigh' },
  IsTacticExpansion:{ color: '#722ed1', symbol: 'diamond',  label: 'TacticExp' },
  IsAdaptingTactics:{ color: '#eb2f96', symbol: 'cross',    label: 'Adapting' },
  IsEmergingEntity: { color: '#13c2c2', symbol: 'circle',   label: 'Emerging' },
}

export default function HistoryPage() {
  const [entities, setEntities] = useState([])
  const [selected, setSelected] = useState(null)  // { name, type }
  const [history, setHistory] = useState([])
  const [loading, setLoading] = useState(false)
  const [loadingList, setLoadingList] = useState(true)
  const { pipelineStatus, selectedEntity, setSelectedEntity } = useApp()

  useEffect(() => {
    setLoadingList(true)
    api.historyList().then(({ data: d }) => {
      setEntities(d?.data ?? [])
      setLoadingList(false)
    })
  }, [pipelineStatus.loaded_file])

  // Cross-module navigation
  useEffect(() => {
    if (selectedEntity) {
      setSelected(selectedEntity)
      setSelectedEntity(null)
    }
  }, [selectedEntity, setSelectedEntity])

  useEffect(() => {
    if (!selected) return
    setLoading(true)
    api.entityHistory(selected.type, selected.name).then(({ data: d }) => {
      setHistory(d?.data ?? [])
      setLoading(false)
    })
  }, [selected])

  if (!loadingList && !pipelineStatus.is_loaded) return <EmptyState />

  const options = entities.map((e) => ({
    value: `${e.EntityType}:${e.EntityName}`,
    label: `[${e.EntityType}] ${e.EntityName} (max ${e.MaxScore?.toFixed(1)}, ${e.RunCount} runs)`,
  }))

  function onSelect(val) {
    const [type, ...rest] = val.split(':')
    setSelected({ type, name: rest.join(':') })
  }

  // Build Plotly traces
  const traces = useMemo(() => {
    if (!history.length) return []

    const x = history.map((r) => r.RunTimestamp?.slice(0, 10))
    const y = history.map((r) => r.SeasonScore)

    const main = {
      type: 'scatter',
      mode: 'lines+markers',
      name: 'Risk score',
      x,
      y,
      line: { color: '#1677ff', width: 2 },
      marker: { color: '#1677ff', size: 5 },
    }

    const flagTraces = Object.entries(ANOMALY_MARKERS).map(([flag, cfg]) => {
      const pts = history.filter((r) => r[flag])
      return {
        type: 'scatter',
        mode: 'markers',
        name: cfg.label,
        x: pts.map((r) => r.RunTimestamp?.slice(0, 10)),
        y: pts.map((r) => r.SeasonScore),
        marker: { color: cfg.color, symbol: cfg.symbol, size: 12 },
      }
    })

    return [main, ...flagTraces]
  }, [history])

  const layout = {
    paper_bgcolor: 'transparent',
    plot_bgcolor: 'transparent',
    font: { color: '#d9d9d9', size: 12 },
    xaxis: { gridcolor: '#2a2a2a', title: 'Run date' },
    yaxis: { gridcolor: '#2a2a2a', title: 'Risk score' },
    legend: { orientation: 'h', y: -0.2 },
    margin: { t: 20, r: 20, b: 60, l: 60 },
  }

  return (
    <div>
      <Space style={{ marginBottom: 16 }} size={12}>
        <AutoComplete
          options={options}
          style={{ width: 400 }}
          placeholder="Search entity…"
          filterOption={(input, opt) =>
            opt.label.toLowerCase().includes(input.toLowerCase())
          }
          onSelect={onSelect}
          loading={loadingList}
        />
        {selected && (
          <Tag color="blue">{selected.type}: {selected.name}</Tag>
        )}
      </Space>

      {!selected ? (
        <Empty description="Select an entity to view its score history" />
      ) : loading ? (
        <Spin size="large" style={{ marginTop: 60, display: 'block' }} />
      ) : history.length === 0 ? (
        <Empty description={`No history found for ${selected.name}`} />
      ) : (
        <Row gutter={16}>
          <Col span={18}>
            <Plot
              data={traces}
              layout={layout}
              config={{ responsive: true, displayModeBar: false }}
              style={{ width: '100%', height: 400 }}
            />
          </Col>
          <Col span={6}>
            <Card size="small" title="Latest run" style={{ marginBottom: 12 }}>
              {(() => {
                const last = history[history.length - 1]
                return (
                  <Space direction="vertical" size={4}>
                    <Text>Score: <Text strong>{last.SeasonScore?.toFixed(1)}</Text></Text>
                    <Text>Episodes: {last.EpisodeCount}</Text>
                    <Text>Tactics: {last.UniqueTactics}</Text>
                    <Text>Top tactic: {last.TopTactic || '—'}</Text>
                    <Text>Top family: {last.TopBehaviorFamily || '—'}</Text>
                    <div style={{ marginTop: 8 }}>
                      {Object.entries(ANOMALY_MARKERS)
                        .filter(([f]) => last[f])
                        .map(([f, cfg]) => (
                          <Tag key={f} color={cfg.color} style={{ marginBottom: 4 }}>
                            {cfg.label}
                          </Tag>
                        ))}
                    </div>
                  </Space>
                )
              })()}
            </Card>
            <Card size="small" title="Legend">
              <Space direction="vertical" size={2}>
                {Object.entries(ANOMALY_MARKERS).map(([, cfg]) => (
                  <Space key={cfg.label} size={6}>
                    <div style={{ width: 12, height: 12, background: cfg.color, borderRadius: 2 }} />
                    <Text style={{ fontSize: 11 }}>{cfg.label}</Text>
                  </Space>
                ))}
              </Space>
            </Card>
          </Col>
        </Row>
      )}
    </div>
  )
}
