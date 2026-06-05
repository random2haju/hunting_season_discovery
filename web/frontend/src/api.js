/**
 * Typed wrappers around the FastAPI backend.
 * All functions return { data, error } — callers never need to catch.
 */

const BASE = '/api'

async function get(path) {
  try {
    const res = await fetch(BASE + path)
    if (!res.ok) {
      const err = await res.json().catch(() => ({ error: res.statusText }))
      return { data: null, error: err.error || res.statusText }
    }
    return { data: await res.json(), error: null }
  } catch (e) {
    return { data: null, error: e.message }
  }
}

async function post(path, body) {
  try {
    const res = await fetch(BASE + path, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: body !== undefined ? JSON.stringify(body) : undefined,
    })
    if (!res.ok) {
      const err = await res.json().catch(() => ({ error: res.statusText }))
      return { data: null, error: err.error || res.statusText }
    }
    return { data: await res.json(), error: null }
  } catch (e) {
    return { data: null, error: e.message }
  }
}

async function del(path) {
  try {
    const res = await fetch(BASE + path, { method: 'DELETE' })
    if (!res.ok) {
      const err = await res.json().catch(() => ({ error: res.statusText }))
      return { data: null, error: err.error || res.statusText }
    }
    return { data: await res.json(), error: null }
  } catch (e) {
    return { data: null, error: e.message }
  }
}

export const api = {
  status:            ()           => get('/status'),
  coverage:          ()           => get('/coverage'),
  insights:          ()           => get('/insights'),
  reload:            ()           => post('/pipeline/reload'),
  priorityCases:     ()           => get('/priority-cases'),
  deviceSeasons:     ()           => get('/seasons/devices'),
  userSeasons:       ()           => get('/seasons/users'),
  allEpisodes:       ()           => get('/episodes'),
  deviceEpisodes:    (name)       => get(`/episodes/${encodeURIComponent(name)}`),
  allUserEpisodes:   ()           => get('/user-episodes'),
  userEpisodes:      (name)       => get(`/user-episodes/${encodeURIComponent(name)}`),
  historyList:       ()           => get('/history'),
  entityHistory:     (type, name) => get(`/history/${type}/${encodeURIComponent(name)}`),
  suppressions:      ()           => get('/suppressions'),
  addSuppression:    (body)       => post('/suppressions', body),
  removeSuppression: (type, name) => del(`/suppressions/${type}/${encodeURIComponent(name)}`),
  expireSuppressions:()           => post('/suppressions/expire'),
  recommendations:   ()           => get('/recommendations'),
  patterns:          ()           => get('/patterns'),
  createPattern:     (body)       => post('/patterns', body),
  deletePattern:     (name)       => del(`/patterns/${encodeURIComponent(name)}`),
  expirePatterns:    ()           => post('/patterns/expire'),
}
