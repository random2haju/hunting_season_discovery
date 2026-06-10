/**
 * Shared triage UI: status tag, quick state picker, and the verdict note modal.
 *
 * Triage states: New (untriaged) → Investigating → Benign | Escalated.
 * 'Reopened' is derived server-side (Benign entity with activity newer than the
 * triage-time snapshot) and is never set directly. Benign/Escalated require a
 * note — the API enforces it; the modal collects it. The Benign modal offers an
 * optional "also suppress" shortcut for entities that will obviously keep firing.
 *
 * Usage:
 *   const { openTriage, triageModal } = useTriageModal({ onChanged })
 *   openTriage(record, 'Benign')   // record needs EntityName/EntityType (or Device/AccountName)
 *   {triageModal}
 */

import React, { useCallback, useState } from 'react'
import { Checkbox, Dropdown, Form, Input, Modal, Tag, Tooltip, message } from 'antd'
import { ClockCircleOutlined } from '@ant-design/icons'
import { api } from '../api'

export const TRIAGE_COLORS = {
  New:           'blue',
  Reopened:      'volcano',
  Investigating: 'gold',
  Escalated:     'red',
  Benign:        'green',
}

export const TRIAGE_STATUSES = Object.keys(TRIAGE_COLORS)

// Analyst-settable states ('Reopened' is derived; 'New' = reset to untriaged)
export const SETTABLE_STATES = ['Investigating', 'Benign', 'Escalated', 'New']
const NEEDS_NOTE = ['Benign', 'Escalated']

function resolveEntity(record) {
  if (!record) return { name: '', type: 'Device' }
  const name = record.EntityName ?? record.DeviceName ?? record.AccountName ?? ''
  const type =
    record.EntityType ?? (record.AccountName && !record.DeviceName ? 'User' : 'Device')
  return { name, type }
}

export function TriageTag({ record, status: statusProp, style }) {
  const status = statusProp ?? record?.TriageStatus ?? 'New'
  const hasNew = !!record?.TriageHasNewActivity && status !== 'Reopened'
  const stale = !!record?.TriageStale

  const tipParts = []
  if (record?.TriageNote) tipParts.push(`"${record.TriageNote}"`)
  if (record?.TriagedBy)
    tipParts.push(`by ${record.TriagedBy}${record.TriagedDate ? ` on ${record.TriagedDate}` : ''}`)
  if (hasNew) tipParts.push('New activity since triage')
  if (stale) tipParts.push('Investigating for a while — stale?')

  const tag = (
    <Tag
      color={TRIAGE_COLORS[status] ?? 'default'}
      icon={stale ? <ClockCircleOutlined /> : null}
      style={{ fontSize: 10, marginRight: 0, ...style }}
    >
      {status}{hasNew ? ' ●' : ''}
    </Tag>
  )
  return tipParts.length ? <Tooltip title={tipParts.join(' — ')}>{tag}</Tooltip> : tag
}

/** Status tag that opens a click-to-change state picker. For table columns. */
export function TriagePicker({ record, openTriage }) {
  return (
    <Dropdown
      trigger={['click']}
      menu={{
        items: SETTABLE_STATES.map((s) => ({
          key: s,
          label: s === 'New' ? 'Reset to New' : `Mark ${s}`,
          onClick: ({ domEvent }) => {
            domEvent.stopPropagation()
            openTriage(record, s)
          },
        })),
      }}
    >
      <span onClick={(e) => e.stopPropagation()} style={{ cursor: 'pointer' }}>
        <TriageTag record={record} />
      </span>
    </Dropdown>
  )
}

/** Submenu items for the entity right-click context menu. */
export function triageMenuChildren(record, openTriage, closeMenu) {
  return SETTABLE_STATES.map((s) => ({
    key: `triage-${s}`,
    label: s === 'New' ? 'Reset to New' : `Mark ${s}`,
    onClick: () => {
      openTriage(record, s)
      closeMenu?.()
    },
  }))
}

export function useTriageModal({ onChanged } = {}) {
  const [modal, setModal] = useState({ open: false, record: null, status: null })
  const [form] = Form.useForm()

  const apply = useCallback(
    async (record, status, note = '', alsoSuppress = false) => {
      const { name, type } = resolveEntity(record)
      const { data, error } = await api.setTriage({
        entity_type: type,
        entity_name: name,
        status,
        note,
        also_suppress: alsoSuppress,
      })
      if (error) {
        message.error(error)
        return false
      }
      if (data?.suppress_error) {
        message.warning(`Triaged, but suppression failed: ${data.suppress_error}`)
      } else {
        message.success(status === 'New' ? `Reset "${name}" to New` : `"${name}" → ${status}`)
      }
      onChanged?.()
      return true
    },
    [onChanged],
  )

  const openTriage = useCallback(
    (record, status) => {
      if (NEEDS_NOTE.includes(status)) {
        setModal({ open: true, record, status })
      } else {
        apply(record, status)
      }
    },
    [apply],
  )

  const close = useCallback(() => {
    setModal({ open: false, record: null, status: null })
    form.resetFields()
  }, [form])

  async function handleFinish(values) {
    const ok = await apply(modal.record, modal.status, values.note, !!values.alsoSuppress)
    if (ok) close()
  }

  const { name: mName } = resolveEntity(modal.record)
  const isBenign = modal.status === 'Benign'

  const triageModal = (
    <Modal
      title={`${isBenign ? 'Mark benign' : 'Escalate'}: ${mName}`}
      open={modal.open}
      onCancel={close}
      onOk={() => form.submit()}
      okText={isBenign ? 'Mark benign' : 'Escalate'}
      okButtonProps={isBenign ? {} : { danger: true }}
      destroyOnClose={false}
    >
      <Form form={form} layout="vertical" onFinish={handleFinish}>
        <Form.Item
          name="note"
          label="Note (required for this verdict)"
          rules={[{ required: true, message: 'A note is required for Benign/Escalated' }]}
        >
          <Input.TextArea
            rows={2}
            autoFocus
            placeholder={
              isBenign
                ? 'What did you review, and why is it benign?'
                : 'What was found, and where was it escalated (ticket, IR case)?'
            }
          />
        </Form.Item>
        {isBenign && (
          <Form.Item name="alsoSuppress" valuePropName="checked" style={{ marginBottom: 0 }}>
            <Checkbox>
              Also suppress this entity permanently (removes it from Priority Cases entirely)
            </Checkbox>
          </Form.Item>
        )}
      </Form>
    </Modal>
  )

  return { openTriage, triageModal }
}
