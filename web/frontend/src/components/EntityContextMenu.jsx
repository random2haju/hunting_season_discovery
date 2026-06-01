/**
 * Right-click context menu for table rows and graph nodes.
 *
 * Usage:
 *   const { contextMenu, onRow, ContextMenuPortal, SuppressModal } = useEntityContextMenu()
 *
 *   <Table onRow={onRow} ... />
 *   <ContextMenuPortal />
 *   <SuppressModal />
 */

import React, { useCallback, useEffect, useRef, useState } from 'react'
import { DatePicker, Form, Input, Menu, message, Modal, Select } from 'antd'
import {
  ApartmentOutlined,
  EyeOutlined,
  StopOutlined,
} from '@ant-design/icons'
import { useApp } from '../context/AppContext'
import { api } from '../api'

export function useEntityContextMenu() {
  const { navigateTo } = useApp()
  const [menu, setMenu] = useState({ open: false, x: 0, y: 0, record: null })
  const [suppressModal, setSuppressModal] = useState({ open: false, record: null })
  const [form] = Form.useForm()
  const menuRef = useRef(null)

  // Close on outside click
  useEffect(() => {
    const handler = () => setMenu((m) => ({ ...m, open: false }))
    document.addEventListener('click', handler)
    return () => document.removeEventListener('click', handler)
  }, [])

  // record: { EntityName|DeviceName|AccountName, EntityType|type, ... }
  const open = useCallback((e, record) => {
    e.preventDefault()
    setMenu({ open: true, x: e.clientX, y: e.clientY, record })
  }, [])

  // Normalise whichever column names the caller passes
  function resolveEntity(record) {
    if (!record) return { name: '', type: 'Device' }
    const name =
      record.EntityName ?? record.DeviceName ?? record.AccountName ?? record.label ?? ''
    const type =
      record.EntityType ??
      (record.type === 'user' ? 'User' : record.type === 'device' ? 'Device' : 'Device')
    return { name, type }
  }

  const menuItems = [
    {
      key: 'suppress',
      icon: <StopOutlined />,
      label: 'Suppress entity',
      onClick: () => {
        setSuppressModal({ open: true, record: menu.record })
        setMenu((m) => ({ ...m, open: false }))
      },
    },
    {
      key: 'graph',
      icon: <ApartmentOutlined />,
      label: 'View in Graph',
      onClick: () => {
        const { name, type } = resolveEntity(menu.record)
        navigateTo(name, type, '/')
        setMenu((m) => ({ ...m, open: false }))
      },
    },
    {
      key: 'episodes',
      icon: <EyeOutlined />,
      label: 'View Episodes',
      onClick: () => {
        const { name, type } = resolveEntity(menu.record)
        navigateTo(name, type, '/episodes')
        setMenu((m) => ({ ...m, open: false }))
      },
    },
  ]

  function ContextMenuPortal() {
    if (!menu.open) return null
    return (
      <div
        ref={menuRef}
        style={{
          position: 'fixed',
          top: menu.y,
          left: menu.x,
          zIndex: 9999,
          boxShadow: '0 4px 12px rgba(0,0,0,0.4)',
          borderRadius: 6,
        }}
        onClick={(e) => e.stopPropagation()}
      >
        <Menu items={menuItems} style={{ borderRadius: 6, minWidth: 180 }} />
      </div>
    )
  }

  async function handleSuppress(values) {
    const { name, type } = resolveEntity(suppressModal.record)
    const body = {
      entity_type: type,
      entity_name: name,
      reason: values.reason,
      expires: values.expires ? values.expires.format('YYYY-MM-DD') : null,
    }
    const { error } = await api.addSuppression(body)
    if (error) {
      message.error(error)
    } else {
      message.success(`Suppressed ${type} "${name}"`)
      setSuppressModal({ open: false, record: null })
      form.resetFields()
    }
  }

  function SuppressModal() {
    const { name, type } = resolveEntity(suppressModal.record)
    return (
      <Modal
        title={`Suppress ${type}: ${name}`}
        open={suppressModal.open}
        onCancel={() => setSuppressModal({ open: false, record: null })}
        onOk={() => form.submit()}
        okText="Suppress"
        okButtonProps={{ danger: true }}
      >
        <Form form={form} layout="vertical" onFinish={handleSuppress}>
          <Form.Item
            name="reason"
            label="Reason"
            rules={[{ required: true, message: 'Please enter a reason' }]}
          >
            <Input placeholder="e.g. Known AI developer workstation" />
          </Form.Item>
          <Form.Item name="expires" label="Expires (optional — leave blank for permanent)">
            <DatePicker style={{ width: '100%' }} format="YYYY-MM-DD" />
          </Form.Item>
        </Form>
      </Modal>
    )
  }

  // onRow callback for antd Table
  const onRow = useCallback(
    (record) => ({
      onContextMenu: (e) => open(e, record),
    }),
    [open],
  )

  return { contextMenu: menu, onRow, ContextMenuPortal, SuppressModal }
}
