import React, { useEffect } from 'react'
import { Route, Routes, useLocation, useNavigate } from 'react-router-dom'
import {
  ApartmentOutlined,
  BarChartOutlined,
  ClockCircleOutlined,
  LineChartOutlined,
  PlayCircleOutlined,
  ReloadOutlined,
  StopOutlined,
  TableOutlined,
  UnorderedListOutlined,
} from '@ant-design/icons'
import { Badge, Button, ConfigProvider, Layout, Menu, Space, Tag, theme, Typography } from 'antd'
import { AppProvider, useApp } from './context/AppContext'
import PipelineDrawer from './components/PipelineDrawer'
import GraphPage from './pages/GraphPage'
import PriorityPage from './pages/PriorityPage'
import SeasonsPage from './pages/SeasonsPage'
import EpisodesPage from './pages/EpisodesPage'
import HistoryPage from './pages/HistoryPage'
import StackingPage from './pages/StackingPage'
import SuppressionsPage from './pages/SuppressionsPage'
import { api } from './api'

const { Header, Sider, Content } = Layout
const { Text } = Typography

const NAV_ITEMS = [
  { key: '/',             icon: <ApartmentOutlined />, label: 'Graph' },
  { key: '/priority',     icon: <TableOutlined />,     label: 'Priority Cases' },
  { key: '/seasons',      icon: <UnorderedListOutlined />, label: 'Seasons' },
  { key: '/episodes',     icon: <ClockCircleOutlined />, label: 'Episode Timeline' },
  { key: '/history',      icon: <LineChartOutlined />, label: 'Historical Trends' },
  { key: '/stacking',     icon: <BarChartOutlined />,  label: 'Stacking Analysis' },
  { key: '/suppressions', icon: <StopOutlined />,      label: 'Suppression Manager' },
]

function Shell() {
  const navigate = useNavigate()
  const location = useLocation()
  const { pipelineStatus, setPipelineStatus, setDrawerOpen } = useApp()

  useEffect(() => {
    api.status().then(({ data }) => data && setPipelineStatus(data))
  }, [setPipelineStatus])

  async function handleReload() {
    const { data, error } = await api.reload()
    if (!error && data) {
      api.status().then(({ data: s }) => s && setPipelineStatus(s))
    }
  }

  const selectedKey = NAV_ITEMS.find((i) => i.key === location.pathname)?.key ?? '/'

  return (
    <Layout style={{ minHeight: '100vh' }}>
      <Sider width={220} theme="dark" collapsible>
        <div
          style={{
            padding: '16px 20px 12px',
            color: '#fff',
            fontWeight: 700,
            fontSize: 14,
            letterSpacing: 0.5,
            borderBottom: '1px solid #2a2a2a',
            whiteSpace: 'nowrap',
            overflow: 'hidden',
          }}
        >
          Threat Hunt
        </div>
        <Menu
          theme="dark"
          mode="inline"
          selectedKeys={[selectedKey]}
          items={NAV_ITEMS}
          onClick={({ key }) => navigate(key)}
          style={{ borderRight: 0 }}
        />
      </Sider>

      <Layout>
        <Header
          style={{
            background: '#141414',
            borderBottom: '1px solid #2a2a2a',
            padding: '0 20px',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'space-between',
          }}
        >
          <Space size={8}>
            <Badge
              status={
                pipelineStatus.is_running
                  ? 'processing'
                  : pipelineStatus.is_loaded
                  ? 'success'
                  : 'default'
              }
            />
            <Text style={{ color: '#888', fontSize: 12 }}>
              {pipelineStatus.is_running
                ? 'Running…'
                : pipelineStatus.loaded_file
                ? pipelineStatus.loaded_file
                : 'No data loaded'}
            </Text>
          </Space>
          <Space>
            <Button
              size="small"
              icon={<ReloadOutlined />}
              onClick={handleReload}
              disabled={pipelineStatus.is_running}
            >
              Reload
            </Button>
            <Button
              size="small"
              type="primary"
              icon={<PlayCircleOutlined />}
              onClick={() => setDrawerOpen(true)}
              disabled={pipelineStatus.is_running}
            >
              Run pipeline
            </Button>
          </Space>
        </Header>

        <Content style={{ padding: 24, overflow: 'auto' }}>
          <Routes>
            <Route path="/"             element={<GraphPage />} />
            <Route path="/priority"     element={<PriorityPage />} />
            <Route path="/seasons"      element={<SeasonsPage />} />
            <Route path="/episodes"     element={<EpisodesPage />} />
            <Route path="/history"      element={<HistoryPage />} />
            <Route path="/stacking"     element={<StackingPage />} />
            <Route path="/suppressions" element={<SuppressionsPage />} />
          </Routes>
        </Content>
      </Layout>

      <PipelineDrawer />
    </Layout>
  )
}

export default function App() {
  return (
    <ConfigProvider
      theme={{
        algorithm: theme.darkAlgorithm,
        token: { colorPrimary: '#1677ff', borderRadius: 6 },
      }}
    >
      <AppProvider>
        <Shell />
      </AppProvider>
    </ConfigProvider>
  )
}
