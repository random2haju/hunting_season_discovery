import React, { useEffect, useState } from 'react'
import {
  Button, DatePicker, Form, Input, message, Modal, Popconfirm,
  Select, Space, Table, Tag, Typography,
} from 'antd'
import { PlusOutlined, SyncOutlined } from '@ant-design/icons'
import { api } from '../api'
import { useApp } from '../context/AppContext'

const { Text } = Typography

const COLS = (onRemove) => [
  {
    title: 'Type',
    dataIndex: 'EntityType',
    key: 'EntityType',
    width: 70,
    filters: [
      { text: 'Device', value: 'Device' },
      { text: 'User', value: 'User' },
    ],
    onFilter: (v, r) => r.EntityType === v,
  },
  {
    title: 'Entity',
    dataIndex: 'EntityName',
    key: 'EntityName',
    ellipsis: true,
    render: (v) => <Text code style={{ fontSize: 12 }}>{v}</Text>,
  },
  {
    title: 'Reason',
    dataIndex: 'Reason',
    key: 'Reason',
    ellipsis: true,
  },
  {
    title: 'Added',
    dataIndex: 'AddedDate',
    key: 'AddedDate',
    width: 100,
  },
  {
    title: 'Expires',
    dataIndex: 'ExpiresDate',
    key: 'ExpiresDate',
    width: 100,
    render: (v) => v || <Text type="secondary">permanent</Text>,
  },
  {
    title: 'Status',
    key: 'status',
    width: 90,
    render: (_, r) =>
      r.expired ? (
        <Tag color="default">Expired</Tag>
      ) : (
        <Tag color="red">Active</Tag>
      ),
    filters: [
      { text: 'Active', value: false },
      { text: 'Expired', value: true },
    ],
    onFilter: (v, r) => !!r.expired === v,
  },
  {
    title: '',
    key: 'actions',
    width: 80,
    render: (_, r) => (
      <Popconfirm
        title={`Remove suppression for "${r.EntityName}"?`}
        onConfirm={() => onRemove(r)}
        okText="Remove"
        okButtonProps={{ danger: true }}
      >
        <Button size="small" danger type="text">
          Remove
        </Button>
      </Popconfirm>
    ),
  },
]

export default function SuppressionsPage() {
  const [rows, setRows] = useState([])
  const [loading, setLoading] = useState(true)
  const [addOpen, setAddOpen] = useState(false)
  const [form] = Form.useForm()
  const { pipelineStatus } = useApp()

  async function load() {
    setLoading(true)
    const { data } = await api.suppressions()
    setRows(data?.data ?? [])
    setLoading(false)
  }

  useEffect(() => { load() }, [pipelineStatus.loaded_file])

  async function handleAdd(values) {
    const body = {
      entity_type: values.entity_type,
      entity_name: values.entity_name,
      reason: values.reason,
      expires: values.expires ? values.expires.format('YYYY-MM-DD') : null,
    }
    const { error } = await api.addSuppression(body)
    if (error) {
      message.error(error)
    } else {
      message.success(`Suppressed ${body.entity_type} "${body.entity_name}"`)
      setAddOpen(false)
      form.resetFields()
      load()
    }
  }

  async function handleRemove(row) {
    const { error } = await api.removeSuppression(row.EntityType, row.EntityName)
    if (error) {
      message.error(error)
    } else {
      message.success(`Removed suppression for "${row.EntityName}"`)
      load()
    }
  }

  async function handleExpire() {
    const { data, error } = await api.expireSuppressions()
    if (error) {
      message.error(error)
    } else {
      message.success(`Pruned ${data.dropped} expired suppression${data.dropped !== 1 ? 's' : ''}`)
      load()
    }
  }

  const active = rows.filter((r) => !r.expired).length

  return (
    <>
      <Space style={{ marginBottom: 12 }}>
        <Button type="primary" icon={<PlusOutlined />} onClick={() => setAddOpen(true)}>
          Add suppression
        </Button>
        <Button icon={<SyncOutlined />} onClick={handleExpire}>
          Prune expired
        </Button>
        <Text type="secondary" style={{ fontSize: 12 }}>
          {active} active · {rows.length - active} expired
        </Text>
      </Space>

      <Table
        dataSource={rows}
        columns={COLS(handleRemove)}
        rowKey={(r) => `${r.EntityType}-${r.EntityName}`}
        loading={loading}
        size="small"
        pagination={{ pageSize: 50 }}
      />

      <Modal
        title="Add suppression"
        open={addOpen}
        onCancel={() => { setAddOpen(false); form.resetFields() }}
        onOk={() => form.submit()}
        okText="Suppress"
        okButtonProps={{ danger: true }}
      >
        <Form form={form} layout="vertical" onFinish={handleAdd}>
          <Form.Item
            name="entity_type"
            label="Entity type"
            rules={[{ required: true }]}
            initialValue="Device"
          >
            <Select options={[{ value: 'Device' }, { value: 'User' }]} />
          </Form.Item>
          <Form.Item
            name="entity_name"
            label="Entity name"
            rules={[{ required: true, message: 'Required' }]}
          >
            <Input placeholder="LAPTOP-AI-DEV01 or svc-scanner" />
          </Form.Item>
          <Form.Item
            name="reason"
            label="Reason"
            rules={[{ required: true, message: 'Required' }]}
          >
            <Input placeholder="e.g. Known AI developer workstation" />
          </Form.Item>
          <Form.Item name="expires" label="Expires (leave blank for permanent)">
            <DatePicker style={{ width: '100%' }} format="YYYY-MM-DD" />
          </Form.Item>
        </Form>
      </Modal>
    </>
  )
}
