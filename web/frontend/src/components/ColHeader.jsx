import React from 'react'
import { Tooltip } from 'antd'
import { QuestionCircleOutlined } from '@ant-design/icons'

export function ColHeader({ label, tip }) {
  return (
    <span style={{ whiteSpace: 'nowrap' }}>
      {label}
      {tip && (
        <Tooltip title={tip} placement="top">
          <QuestionCircleOutlined style={{ marginLeft: 4, fontSize: 11, color: '#8c8c8c', cursor: 'help' }} />
        </Tooltip>
      )}
    </span>
  )
}
