/**
 * Slide-out drawer that streams pipeline stdout via Server-Sent Events.
 * Opens when the user clicks "Run pipeline" from anywhere in the app.
 */

import React, { useEffect, useRef, useState } from 'react'
import { Button, Drawer, Space, Typography } from 'antd'
import { PlayCircleOutlined, ReloadOutlined } from '@ant-design/icons'
import { useApp } from '../context/AppContext'
import { api } from '../api'
import { palette } from '../theme'

const { Text } = Typography

export default function PipelineDrawer() {
  const { drawerOpen, setDrawerOpen, setPipelineStatus } = useApp()
  const [lines, setLines] = useState([])
  const [running, setRunning] = useState(false)
  const [done, setDone] = useState(false)
  const esRef = useRef(null)
  const logEndRef = useRef(null)

  useEffect(() => {
    logEndRef.current?.scrollIntoView({ behavior: 'smooth' })
  }, [lines])

  function startPipeline() {
    setLines([])
    setRunning(true)
    setDone(false)

    if (esRef.current) esRef.current.close()
    const es = new EventSource('/api/pipeline/run')
    esRef.current = es

    es.onmessage = (e) => {
      const msg = JSON.parse(e.data)
      setLines((prev) => [...prev, msg])
      if (msg.type === 'done' || msg.type === 'error') {
        setRunning(false)
        setDone(true)
        es.close()
        // Refresh status badge in header
        api.status().then(({ data }) => data && setPipelineStatus(data))
      }
    }

    es.onerror = () => {
      setLines((prev) => [...prev, { type: 'error', message: 'Connection lost' }])
      setRunning(false)
      setDone(true)
      es.close()
    }
  }

  async function reloadData() {
    setLines([{ type: 'log', message: 'Reloading from existing output…' }])
    setRunning(true)
    const { data, error } = await api.reload()
    setRunning(false)
    setDone(true)
    if (error) {
      setLines((prev) => [...prev, { type: 'error', message: error }])
    } else {
      setLines((prev) => [...prev, { type: 'done', message: `Loaded ${data.loaded_file}` }])
      api.status().then(({ data: s }) => s && setPipelineStatus(s))
    }
  }

  function onClose() {
    if (running && esRef.current) esRef.current.close()
    setDrawerOpen(false)
  }

  const lineColor = { log: palette.text, done: palette.success, error: palette.danger }

  return (
    <Drawer
      title="Pipeline"
      placement="right"
      width={560}
      open={drawerOpen}
      onClose={onClose}
      extra={
        <Space>
          <Button icon={<ReloadOutlined />} onClick={reloadData} disabled={running}>
            Reload
          </Button>
          <Button
            type="primary"
            icon={<PlayCircleOutlined />}
            onClick={startPipeline}
            loading={running}
          >
            Run
          </Button>
        </Space>
      }
    >
      <div
        style={{
          background: palette.bg,
          borderRadius: 6,
          padding: 12,
          fontFamily: 'monospace',
          fontSize: 12,
          height: 'calc(100vh - 160px)',
          overflowY: 'auto',
        }}
      >
        {lines.length === 0 && (
          <Text style={{ color: palette.muted }}>Click Run to start the pipeline…</Text>
        )}
        {lines.map((l, i) => (
          <div key={i} style={{ color: lineColor[l.type] ?? '#d9d9d9', marginBottom: 2 }}>
            {l.message}
          </div>
        ))}
        <div ref={logEndRef} />
      </div>
      {done && !running && (
        <Button
          style={{ marginTop: 12 }}
          block
          onClick={() => setDrawerOpen(false)}
        >
          Close
        </Button>
      )}
    </Drawer>
  )
}
