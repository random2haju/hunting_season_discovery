/**
 * Graph — Cytoscape.js network of devices and users.
 *
 * Nodes: sized and coloured by TotalRisk.
 * Edges: device-user (grey) and device-device shared-account (orange).
 * Layout: Cola (default), Dagre, Concentric.
 * Cross-module: clicking a node opens a detail drawer; right-click shows context menu.
 */

import React, { useEffect, useRef, useState } from 'react'
import cytoscape from 'cytoscape'
import dagre from 'cytoscape-dagre'
import {
  Button, Descriptions, Drawer, Select, Slider, Space, Spin, Tag, Typography,
} from 'antd'
import { ApartmentOutlined, EyeOutlined, StopOutlined } from '@ant-design/icons'
import { api } from '../api'
import EmptyState from '../components/EmptyState'
import { useEntityContextMenu } from '../components/EntityContextMenu'
import { useApp } from '../context/AppContext'

cytoscape.use(dagre)

const { Text } = Typography

const RISK_COLOR = (v) =>
  v >= 50 ? '#ff4d4f' : v >= 20 ? '#fa8c16' : v >= 5 ? '#faad14' : '#52c41a'

const CY_STYLE = [
  {
    selector: 'node',
    style: {
      label: 'data(label)',
      'font-size': 10,
      color: '#d9d9d9',
      'text-valign': 'bottom',
      'text-margin-y': 4,
      'background-color': 'data(color)',
      'border-width': 2,
      'border-color': '#2a2a2a',
      width: 'data(size)',
      height: 'data(size)',
    },
  },
  {
    selector: 'node[type="device"]',
    style: { shape: 'roundrectangle' },
  },
  {
    selector: 'node[type="user"]',
    style: { shape: 'ellipse' },
  },
  {
    selector: 'node.anomaly',
    style: { 'border-color': '#722ed1', 'border-width': 3 },
  },
  {
    selector: 'node.suppressed',
    style: { 'background-color': '#444', 'border-color': '#555', opacity: 0.6 },
  },
  {
    selector: 'node.selected',
    style: { 'border-color': '#1677ff', 'border-width': 4 },
  },
  {
    selector: 'edge[type="device_user"]',
    style: { 'line-color': '#3a3a3a', width: 1, 'curve-style': 'bezier' },
  },
  {
    selector: 'edge[type="shared_account"]',
    style: { 'line-color': '#fa8c16', width: 2, 'curve-style': 'bezier' },
  },
]

function nodeSize(risk) {
  if (risk >= 50) return 40
  if (risk >= 20) return 30
  if (risk >= 5)  return 22
  return 16
}

function buildLayout(name) {
  if (name === 'dagre') return { name: 'dagre', rankDir: 'TB', animate: true }
  if (name === 'concentric') return {
    name: 'concentric',
    concentric: (n) => n.data('risk') ?? 0,
    levelWidth: () => 20,
    animate: true,
  }
  // cose is built-in to Cytoscape — no extension needed, no stack overflow risk
  return { name: 'cose', animate: true, randomize: false, nodeRepulsion: 8000 }
}

export default function GraphPage() {
  const containerRef = useRef(null)
  const cyRef = useRef(null)
  const [graphData, setGraphData] = useState(null)
  const [loading, setLoading] = useState(true)
  const [cyError, setCyError] = useState(null)
  const [layout, setLayout] = useState('cose')
  const [minRisk, setMinRisk] = useState(0)
  const [detailNode, setDetailNode] = useState(null)
  const [drawerOpen, setDrawerOpen] = useState(false)
  const [contextMenu, setContextMenu] = useState({ open: false, x: 0, y: 0, node: null })
  const { pipelineStatus, selectedEntity, setSelectedEntity, navigateTo } = useApp()
  const { SuppressModal, contextMenu: cmState } = useEntityContextMenu()

  // Load graph data
  useEffect(() => {
    setLoading(true)
    api.graph().then(({ data: d }) => {
      setGraphData(d)
      setLoading(false)
    })
  }, [pipelineStatus.loaded_file])

  // Init / rebuild Cytoscape when data or layout changes
  useEffect(() => {
    if (!containerRef.current || !graphData) return

    if (cyRef.current) cyRef.current.destroy()
    setCyError(null)

    const visible = graphData.nodes.filter((n) => (n.risk ?? 0) >= minRisk)
    const visibleIds = new Set(visible.map((n) => n.id))
    const visibleEdges = graphData.edges.filter(
      (e) => visibleIds.has(e.source) && visibleIds.has(e.target),
    )

    const elements = [
      ...visible.map((n) => ({
        data: {
          ...n,
          color: n.isSuppressed ? '#444' : RISK_COLOR(n.risk ?? 0),
          size: nodeSize(n.risk ?? 0),
        },
        classes: [
          n.anomalyFlags?.length ? 'anomaly' : '',
          n.isSuppressed ? 'suppressed' : '',
        ].filter(Boolean).join(' '),
      })),
      ...visibleEdges.map((e) => ({ data: e })),
    ]

    let cy
    try {
      cy = cytoscape({
        container: containerRef.current,
        elements,
        style: CY_STYLE,
        layout: buildLayout(layout),
        userZoomingEnabled: true,
        userPanningEnabled: true,
      })
    } catch (err) {
      console.error('Cytoscape init error:', err)
      setCyError(err.message ?? String(err))
      return
    }

    cy.on('tap', 'node', (evt) => {
      cy.$('.selected').removeClass('selected')
      evt.target.addClass('selected')
      setDetailNode(evt.target.data())
      setDrawerOpen(true)
      setContextMenu({ open: false, x: 0, y: 0, node: null })
    })

    cy.on('tap', (evt) => {
      if (evt.target === cy) setContextMenu({ open: false, x: 0, y: 0, node: null })
    })

    cy.on('cxttap', 'node', (evt) => {
      evt.originalEvent.preventDefault()
      const pos = evt.originalEvent
      setContextMenu({ open: true, x: pos.clientX, y: pos.clientY, node: evt.target.data() })
    })

    cyRef.current = cy
    return () => cy.destroy()
  }, [graphData, layout, minRisk])

  // Cross-module: highlight selected entity
  useEffect(() => {
    if (!selectedEntity || !cyRef.current) return
    const nodeId = `${selectedEntity.type === 'User' ? 'user' : 'device'}:${selectedEntity.name}`
    const node = cyRef.current.$(`#${CSS.escape(nodeId)}`)
    if (node.length) {
      cyRef.current.$('.selected').removeClass('selected')
      node.addClass('selected')
      cyRef.current.animate({ fit: { eles: node, padding: 80 } })
      setDetailNode(node.data())
      setDrawerOpen(true)
    }
    setSelectedEntity(null)
  }, [selectedEntity, setSelectedEntity])

  if (!loading && !pipelineStatus.is_loaded) return <EmptyState />

  const nodeCount = graphData?.nodes.filter((n) => (n.risk ?? 0) >= minRisk).length ?? 0
  const edgeCount = graphData?.edges.length ?? 0

  return (
    <div style={{ position: 'relative', height: 'calc(100vh - 120px)' }}>
      {/* Controls */}
      <Space
        style={{
          position: 'absolute', top: 8, left: 8, zIndex: 10,
          background: '#1a1a1a', padding: '8px 12px', borderRadius: 8,
          boxShadow: '0 2px 8px rgba(0,0,0,0.4)',
        }}
        size={12}
      >
        <Select
          value={layout}
          onChange={setLayout}
          size="small"
          style={{ width: 110 }}
          options={[
            { value: 'cose',       label: 'Cose (default)' },
            { value: 'dagre',      label: 'Dagre' },
            { value: 'concentric', label: 'Concentric' },
          ]}
        />
        <div style={{ width: 140 }}>
          <Text style={{ fontSize: 11, color: '#888' }}>Min risk: {minRisk}</Text>
          <Slider
            min={0} max={50} value={minRisk}
            onChange={setMinRisk} size="small"
            tooltip={{ formatter: (v) => `≥ ${v}` }}
          />
        </div>
        <Text style={{ fontSize: 11, color: '#888' }}>
          {nodeCount} nodes · {edgeCount} edges
        </Text>
      </Space>

      {/* Cytoscape container — always mounted so ref is available after loading */}
      {loading && (
        <Spin size="large" style={{ position: 'absolute', top: '50%', left: '50%' }} />
      )}
      {cyError && (
        <div style={{ position: 'absolute', top: '50%', left: '50%', transform: 'translate(-50%,-50%)',
          color: '#ff4d4f', textAlign: 'center', padding: 24 }}>
          <div style={{ fontWeight: 600, marginBottom: 8 }}>Graph failed to initialise</div>
          <code style={{ fontSize: 12 }}>{cyError}</code>
        </div>
      )}
      <div
        ref={containerRef}
        style={{
          width: '100%', height: '100%', background: '#0d0d0d',
          visibility: loading || cyError ? 'hidden' : 'visible',
        }}
      />

      {/* Node detail drawer */}
      <Drawer
        title={detailNode ? `${detailNode.type === 'user' ? 'User' : 'Device'}: ${detailNode.label}` : ''}
        placement="right"
        width={340}
        open={drawerOpen}
        onClose={() => setDrawerOpen(false)}
        extra={
          detailNode && (
            <Space>
              <Button
                size="small"
                icon={<EyeOutlined />}
                onClick={() => {
                  navigateTo(detailNode.label, detailNode.type === 'user' ? 'User' : 'Device', '/episodes')
                  setDrawerOpen(false)
                }}
              >
                Episodes
              </Button>
            </Space>
          )
        }
      >
        {detailNode && (
          <Descriptions column={1} size="small" bordered>
            <Descriptions.Item label="Risk">
              <Text strong style={{ color: RISK_COLOR(detailNode.risk ?? 0) }}>
                {detailNode.risk?.toFixed(1) ?? '—'}
              </Text>
            </Descriptions.Item>
            <Descriptions.Item label="Episodes">{detailNode.episodeCount}</Descriptions.Item>
            <Descriptions.Item label="Tactics">{detailNode.uniqueTactics}</Descriptions.Item>
            <Descriptions.Item label="Tactic Set">
              <Text style={{ fontSize: 11 }}>{detailNode.tacticSet || '—'}</Text>
            </Descriptions.Item>
            <Descriptions.Item label="Workflow">{detailNode.workflowClass}</Descriptions.Item>
            <Descriptions.Item label="Eligible">
              {detailNode.eligible ? <Tag color="green">Yes</Tag> : <Tag color="default">No</Tag>}
            </Descriptions.Item>
            <Descriptions.Item label="Anomalies">
              <Space wrap size={4}>
                {(detailNode.anomalyFlags ?? []).map((f) => (
                  <Tag key={f} color="purple" style={{ fontSize: 10 }}>{f.replace('Is', '')}</Tag>
                ))}
                {!detailNode.anomalyFlags?.length && <Text type="secondary">None</Text>}
              </Space>
            </Descriptions.Item>
            {detailNode.isSuppressed && (
              <Descriptions.Item label="Suppressed">
                <Tag color="red">Yes</Tag>
              </Descriptions.Item>
            )}
          </Descriptions>
        )}
      </Drawer>

      {/* Right-click context menu */}
      {contextMenu.open && contextMenu.node && (
        <div
          style={{
            position: 'fixed', top: contextMenu.y, left: contextMenu.x,
            zIndex: 9999, background: '#1a1a1a',
            borderRadius: 6, boxShadow: '0 4px 12px rgba(0,0,0,0.5)',
            minWidth: 180, overflow: 'hidden',
          }}
          onClick={() => setContextMenu({ ...contextMenu, open: false })}
        >
          {[
            {
              icon: <StopOutlined />,
              label: 'Suppress entity',
              onClick: () => {
                // Reuse the SuppressModal by injecting record into context
                const n = contextMenu.node
                cmState.record = {
                  EntityName: n.label,
                  EntityType: n.type === 'user' ? 'User' : 'Device',
                }
              },
            },
            {
              icon: <ApartmentOutlined />,
              label: 'View in Graph',
              onClick: () => {
                const n = contextMenu.node
                cyRef.current.$('.selected').removeClass('selected')
                cyRef.current.$(`#${CSS.escape(n.id)}`).addClass('selected')
              },
            },
            {
              icon: <EyeOutlined />,
              label: 'View Episodes',
              onClick: () => {
                const n = contextMenu.node
                navigateTo(n.label, n.type === 'user' ? 'User' : 'Device', '/episodes')
              },
            },
          ].map((item) => (
            <div
              key={item.label}
              style={{
                padding: '8px 14px', cursor: 'pointer', display: 'flex',
                alignItems: 'center', gap: 8, color: '#d9d9d9', fontSize: 13,
              }}
              onMouseEnter={(e) => (e.currentTarget.style.background = '#2a2a2a')}
              onMouseLeave={(e) => (e.currentTarget.style.background = 'transparent')}
              onClick={(e) => { e.stopPropagation(); item.onClick() }}
            >
              {item.icon} {item.label}
            </div>
          ))}
        </div>
      )}

      <SuppressModal />
    </div>
  )
}
