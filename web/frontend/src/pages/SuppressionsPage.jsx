import React, { useCallback, useEffect, useState } from 'react'
import {
  Alert, Button, Collapse, DatePicker, Form, Input, message, Modal,
  Popconfirm, Select, Space, Table, Tabs, Tag, Tooltip, Typography,
} from 'antd'
import {
  BulbOutlined, DeleteOutlined, PlusOutlined, StopOutlined, SyncOutlined,
} from '@ant-design/icons'
import { api } from '../api'
import { useApp } from '../context/AppContext'
import { palette } from '../theme'

const { Text } = Typography

// ---------------------------------------------------------------------------
// Field metadata for pattern conditions
// ---------------------------------------------------------------------------

const FIELDS = [
  { value: 'EntityType',           label: 'Entity Type',          type: 'categorical' },
  { value: 'PrimaryWorkflowClass', label: 'Workflow Class',        type: 'categorical' },
  { value: 'UniqueTactics',        label: 'Unique Tactics',        type: 'numeric' },
  { value: 'TotalRisk',            label: 'Total Risk Score',      type: 'numeric' },
  { value: 'AIWorkflowScenePct',   label: 'AI Workflow Scene %',   type: 'numeric' },
]

const CAT_VALUES = {
  EntityType:           ['Device', 'User'],
  PrimaryWorkflowClass: ['AIWorkflow', 'DeveloperAutomation', 'ServiceAutomation', 'Operational'],
}

const NUMERIC_OPS = [
  { value: '=',  label: '=' },
  { value: '<',  label: '<' },
  { value: '<=', label: '≤' },
  { value: '>',  label: '>' },
  { value: '>=', label: '≥' },
]

function fieldType(fieldName) {
  return FIELDS.find((f) => f.value === fieldName)?.type ?? 'numeric'
}

// ---------------------------------------------------------------------------
// Condition display tag
// ---------------------------------------------------------------------------

function ConditionTag({ cond }) {
  const ft = fieldType(cond.field)
  const opLabel = ft === 'categorical' ? '=' : cond.op
  return (
    <Tag style={{ fontFamily: 'monospace', fontSize: 11 }}>
      {cond.field} {opLabel} {cond.value}
    </Tag>
  )
}

// ---------------------------------------------------------------------------
// Pattern condition builder row
// ---------------------------------------------------------------------------

function ConditionRow({ index, condition, onChange, onRemove, canRemove }) {
  const ft = fieldType(condition.field)

  function handleField(field) {
    const newType = fieldType(field)
    onChange(index, {
      field,
      op: newType === 'categorical' ? '=' : '<=',
      value: newType === 'categorical' ? (CAT_VALUES[field]?.[0] ?? '') : '',
    })
  }

  function handleOp(op)    { onChange(index, { ...condition, op }) }
  function handleValue(val) { onChange(index, { ...condition, value: val }) }

  return (
    <Space size={6} style={{ marginBottom: 8, display: 'flex', alignItems: 'center' }}>
      <Select
        value={condition.field}
        onChange={handleField}
        style={{ width: 190 }}
        options={FIELDS.map((f) => ({ value: f.value, label: f.label }))}
        size="small"
      />
      {ft === 'categorical' ? (
        <Text type="secondary" style={{ width: 36, textAlign: 'center', fontSize: 13 }}>=</Text>
      ) : (
        <Select
          value={condition.op}
          onChange={handleOp}
          style={{ width: 60 }}
          options={NUMERIC_OPS}
          size="small"
        />
      )}
      {ft === 'categorical' ? (
        <Select
          value={condition.value}
          onChange={handleValue}
          style={{ width: 200 }}
          options={(CAT_VALUES[condition.field] ?? []).map((v) => ({ value: v, label: v }))}
          size="small"
        />
      ) : (
        <Input
          value={condition.value}
          onChange={(e) => handleValue(e.target.value)}
          style={{ width: 100 }}
          size="small"
          type="number"
          placeholder="value"
        />
      )}
      {canRemove && (
        <Button
          size="small"
          type="text"
          danger
          icon={<DeleteOutlined />}
          onClick={() => onRemove(index)}
        />
      )}
    </Space>
  )
}

// ---------------------------------------------------------------------------
// Add pattern modal
// ---------------------------------------------------------------------------

function AddPatternModal({ open, onClose, onCreated }) {
  const [name, setName]       = useState('')
  const [reason, setReason]   = useState('')
  const [expires, setExpires] = useState(null)
  const [conditions, setConditions] = useState([
    { field: 'PrimaryWorkflowClass', op: '=', value: 'AIWorkflow' },
  ])
  const [saving, setSaving] = useState(false)

  function reset() {
    setName(''); setReason(''); setExpires(null)
    setConditions([{ field: 'PrimaryWorkflowClass', op: '=', value: 'AIWorkflow' }])
  }

  function handleClose() { reset(); onClose() }

  function updateCond(i, cond) {
    setConditions((prev) => prev.map((c, idx) => (idx === i ? cond : c)))
  }
  function addCond() {
    setConditions((prev) => [...prev, { field: 'UniqueTactics', op: '<=', value: '1' }])
  }
  function removeCond(i) {
    setConditions((prev) => prev.filter((_, idx) => idx !== i))
  }

  async function handleSave() {
    if (!name.trim()) { message.error('Pattern name is required'); return }
    if (!reason.trim()) { message.error('Reason is required'); return }
    for (const c of conditions) {
      if (c.value === '' || c.value === undefined) {
        message.error(`Value missing for condition on field "${c.field}"`); return
      }
    }

    setSaving(true)
    const body = {
      name: name.trim(),
      reason: reason.trim(),
      conditions,
      expires_date: expires ? expires.format('YYYY-MM-DD') : null,
    }
    const { error } = await api.createPattern(body)
    setSaving(false)
    if (error) {
      message.error(error)
    } else {
      message.success(`Pattern '${body.name}' created`)
      reset()
      onCreated()
    }
  }

  return (
    <Modal
      title="Create pattern suppression rule"
      open={open}
      onCancel={handleClose}
      onOk={handleSave}
      okText="Create pattern"
      okButtonProps={{ danger: true, loading: saving }}
      width={620}
      destroyOnClose={false}
    >
      <Form layout="vertical" style={{ marginTop: 8 }}>
        <Form.Item label="Pattern name" required>
          <Input
            value={name}
            onChange={(e) => setName(e.target.value)}
            placeholder="e.g. single-tactic-aiworkflow"
            autoFocus
          />
        </Form.Item>

        <Form.Item label="Reason" required>
          <Input.TextArea
            value={reason}
            onChange={(e) => setReason(e.target.value)}
            rows={2}
            placeholder="Why should matching entities be suppressed?"
          />
        </Form.Item>

        <Form.Item label="Conditions (ALL must match)">
          {conditions.map((cond, i) => (
            <ConditionRow
              key={i}
              index={i}
              condition={cond}
              onChange={updateCond}
              onRemove={removeCond}
              canRemove={conditions.length > 1}
            />
          ))}
          <Button
            size="small"
            icon={<PlusOutlined />}
            onClick={addCond}
            style={{ marginTop: 4 }}
          >
            Add condition
          </Button>
        </Form.Item>

        <Form.Item label="Expires (leave blank for permanent)">
          <DatePicker
            value={expires}
            onChange={setExpires}
            style={{ width: '100%' }}
            format="YYYY-MM-DD"
          />
        </Form.Item>
      </Form>
    </Modal>
  )
}

// ---------------------------------------------------------------------------
// Pattern rules tab
// ---------------------------------------------------------------------------

function PatternRulesTab() {
  const [patterns, setPatterns] = useState([])
  const [loading, setLoading]   = useState(true)
  const [addOpen, setAddOpen]   = useState(false)

  async function load() {
    setLoading(true)
    const { data } = await api.patterns()
    setPatterns(data?.data ?? [])
    setLoading(false)
  }

  useEffect(() => { load() }, [])

  async function handleDelete(name) {
    const { error } = await api.deletePattern(name)
    if (error) { message.error(error) }
    else { message.success(`Pattern '${name}' deleted`); load() }
  }

  async function handleExpire() {
    const { data, error } = await api.expirePatterns()
    if (error) { message.error(error) }
    else {
      message.success(`Pruned ${data.dropped} expired pattern${data.dropped !== 1 ? 's' : ''}`)
      load()
    }
  }

  const active = patterns.filter((p) => !p.expired).length

  const cols = [
    {
      title: 'Name',
      dataIndex: 'name',
      key: 'name',
      width: 200,
      render: (v, r) => (
        <Space direction="vertical" size={2}>
          <Text strong style={{ fontSize: 13 }}>{v}</Text>
          {r.expired && <Tag color="default" style={{ fontSize: 10 }}>Expired</Tag>}
        </Space>
      ),
    },
    {
      title: 'Conditions',
      key: 'conditions',
      render: (_, r) => (
        <Space size={4} wrap>
          {(r.conditions ?? []).map((c, i) => (
            <ConditionTag key={i} cond={c} />
          ))}
        </Space>
      ),
    },
    {
      title: 'Reason',
      dataIndex: 'reason',
      key: 'reason',
      ellipsis: true,
    },
    {
      title: 'Added',
      dataIndex: 'added_date',
      key: 'added_date',
      width: 100,
    },
    {
      title: 'Expires',
      dataIndex: 'expires_date',
      key: 'expires_date',
      width: 100,
      render: (v) => v || <Text type="secondary">permanent</Text>,
    },
    {
      title: '',
      key: 'actions',
      width: 80,
      render: (_, r) => (
        <Popconfirm
          title={`Delete pattern "${r.name}"?`}
          onConfirm={() => handleDelete(r.name)}
          okText="Delete"
          okButtonProps={{ danger: true }}
        >
          <Button size="small" danger type="text" icon={<DeleteOutlined />}>
            Delete
          </Button>
        </Popconfirm>
      ),
    },
  ]

  return (
    <>
      <Space style={{ marginBottom: 12 }}>
        <Button type="primary" danger icon={<StopOutlined />} onClick={() => setAddOpen(true)}>
          New pattern rule
        </Button>
        <Button icon={<SyncOutlined />} onClick={handleExpire}>
          Prune expired
        </Button>
        <Text type="secondary" style={{ fontSize: 12 }}>
          {active} active · {patterns.length - active} expired
        </Text>
      </Space>

      {patterns.length === 0 && !loading && (
        <Alert
          type="info"
          message="No pattern rules yet"
          description='Create a rule to automatically suppress classes of entities — e.g. all AIWorkflow devices with a single MITRE tactic and risk score below 10.'
          style={{ marginBottom: 12 }}
        />
      )}

      <Table
        dataSource={patterns}
        columns={cols}
        rowKey="name"
        loading={loading}
        size="small"
        pagination={{ pageSize: 50 }}
      />

      <AddPatternModal
        open={addOpen}
        onClose={() => setAddOpen(false)}
        onCreated={() => { setAddOpen(false); load() }}
      />
    </>
  )
}

// ---------------------------------------------------------------------------
// Active suppressions tab (entity-level)
// ---------------------------------------------------------------------------

const SUPP_COLS = (onRemove) => [
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
      r.expired ? <Tag color="default">Expired</Tag> : <Tag color="red">Active</Tag>,
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
        <Button size="small" danger type="text">Remove</Button>
      </Popconfirm>
    ),
  },
]

function ActiveSuppressionsTab() {
  const [rows, setRows]     = useState([])
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
    if (error) { message.error(error) }
    else { message.success(`Removed suppression for "${row.EntityName}"`); load() }
  }

  async function handleExpire() {
    const { data, error } = await api.expireSuppressions()
    if (error) { message.error(error) }
    else {
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
        columns={SUPP_COLS(handleRemove)}
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
        destroyOnClose={false}
      >
        <Form form={form} layout="vertical" onFinish={handleAdd}>
          <Form.Item name="entity_type" label="Entity type" rules={[{ required: true }]} initialValue="Device">
            <Select options={[{ value: 'Device' }, { value: 'User' }]} />
          </Form.Item>
          <Form.Item name="entity_name" label="Entity name" rules={[{ required: true, message: 'Required' }]}>
            <Input placeholder="LAPTOP-AI-DEV01 or svc-scanner" autoFocus />
          </Form.Item>
          <Form.Item name="reason" label="Reason" rules={[{ required: true, message: 'Required' }]}>
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

// ---------------------------------------------------------------------------
// Recommendations panel
// ---------------------------------------------------------------------------

function RecommendationsPanel({ onSuppressed }) {
  const [recs, setRecs]     = useState([])
  const [loading, setLoading] = useState(false)
  const [target, setTarget] = useState(null)
  const [form] = Form.useForm()

  async function load() {
    setLoading(true)
    const { data, error } = await api.recommendations()
    if (!error) setRecs(data?.data ?? [])
    setLoading(false)
  }

  useEffect(() => { load() }, [])

  const openSuppress = useCallback((rec) => {
    setTarget(rec)
    setTimeout(() => form.setFieldsValue({ reason: rec.SuggestedReason }), 0)
  }, [form])

  async function handleSuppress(values) {
    const body = {
      entity_type: target.EntityType,
      entity_name: target.EntityName,
      reason: values.reason,
      expires: values.expires ? values.expires.format('YYYY-MM-DD') : null,
    }
    const { error } = await api.addSuppression(body)
    if (error) {
      message.error(error)
    } else {
      message.success(`Suppressed ${target.EntityType} "${target.EntityName}"`)
      setTarget(null)
      form.resetFields()
      setRecs((prev) => prev.filter(
        (r) => !(r.EntityType === target.EntityType && r.EntityName === target.EntityName)
      ))
      onSuppressed()
    }
  }

  const cols = [
    {
      title: 'Type', dataIndex: 'EntityType', key: 'EntityType', width: 70,
      filters: [{ text: 'Device', value: 'Device' }, { text: 'User', value: 'User' }],
      onFilter: (v, r) => r.EntityType === v,
    },
    {
      title: 'Entity', dataIndex: 'EntityName', key: 'EntityName', ellipsis: true,
      render: (v) => <Text code style={{ fontSize: 12 }}>{v}</Text>,
    },
    {
      title: 'Runs', dataIndex: 'RunCount', key: 'RunCount', width: 65,
      sorter: (a, b) => a.RunCount - b.RunCount, defaultSortOrder: 'descend',
    },
    {
      title: 'Avg Score', dataIndex: 'AvgScore', key: 'AvgScore', width: 90,
      sorter: (a, b) => a.AvgScore - b.AvgScore,
    },
    {
      title: 'Max Score', dataIndex: 'MaxScore', key: 'MaxScore', width: 90,
      sorter: (a, b) => a.MaxScore - b.MaxScore,
    },
    {
      title: 'Stability', dataIndex: 'MaxAvgRatio', key: 'MaxAvgRatio', width: 85,
      sorter: (a, b) => a.MaxAvgRatio - b.MaxAvgRatio,
      render: (v) => (
        <Tooltip title="max/avg score ratio — closer to 1.0 = perfectly flat">
          <Text style={{ fontSize: 12, color: v < 1.2 ? '#52c41a' : '#faad14' }}>{v}×</Text>
        </Tooltip>
      ),
    },
    {
      title: 'Top Tactic', dataIndex: 'TopTactic', key: 'TopTactic', ellipsis: true,
      render: (v) => v ? <Tag style={{ fontSize: 11 }}>{v}</Tag> : null,
    },
    {
      title: '', key: 'action', width: 90,
      render: (_, r) => (
        <Button size="small" danger onClick={() => openSuppress(r)}>Suppress</Button>
      ),
    },
  ]

  if (!loading && recs.length === 0) {
    return (
      <Alert
        type="success"
        message="No stable-noise candidates found"
        description="Entities need at least 3 runs with a stable score profile to appear here."
      />
    )
  }

  return (
    <>
      <Alert
        type="info" showIcon icon={<BulbOutlined />}
        message={`${recs.length} suppression candidate${recs.length !== 1 ? 's' : ''} found`}
        description="These entities appeared in multiple runs with stable, non-spiking scores — likely benign noise."
        style={{ marginBottom: 12 }}
      />
      <Table
        dataSource={recs} columns={cols}
        rowKey={(r) => `${r.EntityType}-${r.EntityName}`}
        loading={loading} size="small"
        pagination={{ pageSize: 20, showSizeChanger: true }}
      />
      <Modal
        title={target ? `Suppress ${target.EntityType}: ${target.EntityName}` : 'Suppress entity'}
        open={!!target}
        onCancel={() => { setTarget(null); form.resetFields() }}
        onOk={() => form.submit()}
        okText="Suppress" okButtonProps={{ danger: true }}
        destroyOnClose={false}
      >
        <Form form={form} layout="vertical" onFinish={handleSuppress}>
          <Form.Item name="reason" label="Reason" rules={[{ required: true, message: 'Required' }]}>
            <Input.TextArea rows={3} autoFocus />
          </Form.Item>
          <Form.Item name="expires" label="Expires (leave blank for permanent)">
            <DatePicker style={{ width: '100%' }} format="YYYY-MM-DD" />
          </Form.Item>
        </Form>
      </Modal>
    </>
  )
}

// ---------------------------------------------------------------------------
// Page
// ---------------------------------------------------------------------------

export default function SuppressionsPage() {
  const [reloadKey, setReloadKey] = useState(0)

  return (
    <>
      <Collapse
        defaultActiveKey={[]}
        style={{ marginBottom: 16 }}
        items={[
          {
            key: 'recs',
            label: (
              <Space>
                <BulbOutlined style={{ color: palette.amber }} />
                <Text strong>Suppression Recommendations</Text>
                <Text type="secondary" style={{ fontSize: 12 }}>
                  — stable-noise entities from run history
                </Text>
              </Space>
            ),
            children: <RecommendationsPanel onSuppressed={() => setReloadKey((k) => k + 1)} />,
          },
        ]}
      />

      <Tabs
        defaultActiveKey="suppressions"
        items={[
          {
            key: 'suppressions',
            label: 'Active Suppressions',
            children: <ActiveSuppressionsTab key={reloadKey} />,
          },
          {
            key: 'patterns',
            label: 'Pattern Rules',
            children: <PatternRulesTab />,
          },
        ]}
      />
    </>
  )
}
