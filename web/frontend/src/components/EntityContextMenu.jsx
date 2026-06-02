/**
 * Right-click context menu for table rows and graph nodes.
 *
 * Usage:
 *   const { onRow, contextMenuPortal, suppressModal, openSuppressModal } = useEntityContextMenu()
 *
 *   <Table onRow={onRow} ... />
 *   {contextMenuPortal}
 *   {suppressModal}
 *
 * For programmatic use (e.g. graph node click):
 *   openSuppressModal({ EntityName: 'FOO', EntityType: 'Device' })
 */

import React, { useCallback, useEffect, useRef, useState } from 'react'
import { DatePicker, Form, Input, Menu, message, Modal } from 'antd'
import {
  ApartmentOutlined,
  EyeOutlined,
  InfoCircleOutlined,
  StopOutlined,
} from '@ant-design/icons'
import { useApp } from '../context/AppContext'
import { api } from '../api'

function resolveEntity(record) {
  if (!record) return { name: '', type: 'Device' }
  const name =
    record.EntityName ?? record.DeviceName ?? record.AccountName ?? record.label ?? ''
  const type =
    record.EntityType ??
    (record.type === 'user' ? 'User' : record.type === 'device' ? 'Device' : 'Device')
  return { name, type }
}

export function useEntityContextMenu({ onViewDetails } = {}) {
  const { navigateTo } = useApp()
  const [menu, setMenu] = useState({ open: false, x: 0, y: 0, record: null })
  const [suppressState, setSuppressState] = useState({ open: false, record: null })
  const [form] = Form.useForm()
  const menuRef = useRef(null)

  // Close context menu on outside click
  useEffect(() => {
    const handler = () => setMenu((m) => ({ ...m, open: false }))
    document.addEventListener('click', handler)
    return () => document.removeEventListener('click', handler)
  }, [])

  const openContextMenu = useCallback((e, record) => {
    e.preventDefault()
    setMenu({ open: true, x: e.clientX, y: e.clientY, record })
  }, [])

  const openSuppressModal = useCallback((record) => {
    setSuppressState({ open: true, record })
  }, [])

  const closeSuppress = useCallback(() => {
    setSuppressState({ open: false, record: null })
    form.resetFields()
  }, [form])

  const menuItems = [
    ...(onViewDetails ? [{
      key: 'details',
      icon: <InfoCircleOutlined />,
      label: 'View details',
      onClick: () => {
        onViewDetails(menu.record)
        setMenu((m) => ({ ...m, open: false }))
      },
    }] : []),
    {
      key: 'suppress',
      icon: <StopOutlined />,
      label: 'Suppress entity',
      onClick: () => {
        openSuppressModal(menu.record)
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

  async function handleSuppress(values) {
    const { name, type } = resolveEntity(suppressState.record)
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
      closeSuppress()
    }
  }

  // onRow callback for antd Table
  const onRow = useCallback(
    (record) => ({
      onContextMenu: (e) => openContextMenu(e, record),
    }),
    [openContextMenu],
  )

  const { name: sName, type: sType } = resolveEntity(suppressState.record)

  // Return JSX nodes (not component functions) so React never unmounts them mid-interaction
  const contextMenuPortal = menu.open ? (
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
  ) : null

  const suppressModal = (
    <Modal
      title={`Suppress ${sType}: ${sName}`}
      open={suppressState.open}
      onCancel={closeSuppress}
      onOk={() => form.submit()}
      okText="Suppress"
      okButtonProps={{ danger: true }}
      destroyOnClose={false}
    >
      <Form form={form} layout="vertical" onFinish={handleSuppress}>
        <Form.Item
          name="reason"
          label="Reason"
          rules={[{ required: true, message: 'Please enter a reason' }]}
        >
          <Input placeholder="e.g. Known AI developer workstation" autoFocus />
        </Form.Item>
        <Form.Item name="expires" label="Expires (optional — leave blank for permanent)">
          <DatePicker style={{ width: '100%' }} format="YYYY-MM-DD" />
        </Form.Item>
      </Form>
    </Modal>
  )

  return { contextMenu: menu, onRow, contextMenuPortal, suppressModal, openSuppressModal }
}
