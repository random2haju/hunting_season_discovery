import React from 'react'
import { Button, Result } from 'antd'
import { PlayCircleOutlined } from '@ant-design/icons'
import { useApp } from '../context/AppContext'

export default function EmptyState({ message = 'No data loaded' }) {
  const { setDrawerOpen } = useApp()
  return (
    <Result
      status="info"
      title={message}
      subTitle="Run the pipeline to load threat hunt data, or reload from existing output."
      extra={[
        <Button
          key="run"
          type="primary"
          icon={<PlayCircleOutlined />}
          onClick={() => setDrawerOpen(true)}
        >
          Run pipeline
        </Button>,
      ]}
    />
  )
}
