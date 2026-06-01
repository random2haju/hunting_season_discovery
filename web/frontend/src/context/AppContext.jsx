/**
 * Global app state shared across modules:
 *   - pipelineStatus   — loaded_file, is_loaded, is_running
 *   - selectedEntity   — {name, type} used for cross-module navigation
 *   - navigateTo()     — jump to a module and pre-select an entity
 */

import React, { createContext, useCallback, useContext, useState } from 'react'
import { useNavigate } from 'react-router-dom'

const Ctx = createContext(null)

export function AppProvider({ children }) {
  const navigate = useNavigate()

  const [pipelineStatus, setPipelineStatus] = useState({
    is_loaded: false,
    is_running: false,
    loaded_file: null,
    error: null,
  })

  // The currently highlighted entity — consumed by Graph, Episodes, Seasons
  const [selectedEntity, setSelectedEntity] = useState(null) // { name, type }

  // Drawer state for pipeline log stream
  const [drawerOpen, setDrawerOpen] = useState(false)

  const navigateTo = useCallback(
    (name, type, module) => {
      setSelectedEntity({ name, type })
      navigate(module)
    },
    [navigate],
  )

  return (
    <Ctx.Provider
      value={{
        pipelineStatus,
        setPipelineStatus,
        selectedEntity,
        setSelectedEntity,
        drawerOpen,
        setDrawerOpen,
        navigateTo,
      }}
    >
      {children}
    </Ctx.Provider>
  )
}

export function useApp() {
  return useContext(Ctx)
}
