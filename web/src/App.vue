<script setup lang="ts">
import { computed, onBeforeUnmount, onMounted, ref } from 'vue'

type Page = 'overview' | 'exits' | 'rules' | 'runtime' | 'system'

type ServiceState = Record<string, string>
interface Overview {
  services: ServiceState
  default_exit: string
  proxy_count: number
  group_count: number
  rule_count: number
}
interface Exit {
  tag: string
  type: string
  server: string | null
  server_port: number | null
  tls: boolean
  members: string[]
  default: boolean
  deletable: boolean
  references: number
}
interface Rule {
  kind: 'domain' | 'direct' | 'ruleset'
  value: string
  label: string
  target: string
  count?: number
}
interface Preview {
  tag: string
  type: string
  server: string
  server_port: number
  tls: boolean
  replacing: boolean
}
interface DelayResult {
  tag: string
  ok: boolean
  delay: number | null
}
interface Ruleset {
  tag: string
  label: string
  url: string
  target: string
  format: string
  count: number | null
  available: boolean
}
interface RouteResult {
  domain: string
  target: string
  kind: string
  match: string
}
interface Connection {
  id: string
  host: string
  source: string | null
  network: string | null
  type: string | null
  chains: string[]
  upload: number
  download: number
  start: string | null
}
interface RuntimeState {
  connections: Connection[]
  upload_total: number
  download_total: number
}

const fragmentToken = new URLSearchParams(location.hash.slice(1)).get('token') || ''
if (fragmentToken) {
  localStorage.setItem('pdg-admin-token', fragmentToken)
  history.replaceState(null, '', location.pathname + location.search)
}

const token = ref(localStorage.getItem('pdg-admin-token') || '')
const tokenInput = ref('')
const page = ref<Page>('overview')
const loading = ref(false)
const error = ref('')
const notice = ref('')
const overview = ref<Overview | null>(null)
const exits = ref<Exit[]>([])
const rules = ref<Rule[]>([])
const rulesets = ref<Ruleset[]>([])
const delays = ref<Record<string, DelayResult>>({})
const runtime = ref<RuntimeState | null>(null)
const logs = ref<string[]>([])
const testing = ref(false)
const showAdd = ref(false)
const link = ref('')
const preview = ref<Preview | null>(null)
const search = ref('')
const ruleDomain = ref('')
const ruleTarget = ref('direct')
const routeDomain = ref('')
const routeResult = ref<RouteResult | null>(null)
const groupName = ref('')
const groupMembers = ref<string[]>([])
const showGroup = ref(false)
const editingGroup = ref(false)
const rulesetUrl = ref('')
const rulesetLabel = ref('')
const rulesetTarget = ref('direct')

const concreteExits = computed(() => exits.value.filter(item => item.type !== 'urltest'))

const filteredRules = computed(() => {
  const query = search.value.trim().toLowerCase()
  if (!query) return rules.value
  return rules.value.filter(item => `${item.label} ${item.target} ${item.kind}`.toLowerCase().includes(query))
})

const navItems: { id: Page; label: string; icon: string }[] = [
  { id: 'overview', label: '概览', icon: '◫' },
  { id: 'exits', label: '出口', icon: '⇄' },
  { id: 'rules', label: '分流', icon: '⌘' },
  { id: 'runtime', label: '连接', icon: '↯' },
  { id: 'system', label: '系统', icon: '⚙' },
]

async function api<T>(path: string, options: RequestInit = {}): Promise<T> {
  const response = await fetch(path, {
    ...options,
    headers: {
      Authorization: `Bearer ${token.value}`,
      ...(options.body ? { 'Content-Type': 'application/json' } : {}),
      ...(options.headers || {}),
    },
  })
  const payload = await response.json()
  if (!response.ok) {
    if (response.status === 401) {
      localStorage.removeItem('pdg-admin-token')
      token.value = ''
    }
    throw new Error(payload.error?.message || `请求失败 (${response.status})`)
  }
  return payload.data as T
}

function flash(message: string) {
  notice.value = message
  window.setTimeout(() => {
    if (notice.value === message) notice.value = ''
  }, 2600)
}

async function loadAll() {
  if (!token.value) return
  loading.value = true
  error.value = ''
  try {
    const [summary, exitList, ruleList, rulesetList] = await Promise.all([
      api<Overview>('/api/v1/overview'),
      api<Exit[]>('/api/v1/exits'),
      api<Rule[]>('/api/v1/rules'),
      api<Ruleset[]>('/api/v1/rulesets'),
    ])
    overview.value = summary
    exits.value = exitList
    rules.value = ruleList
    rulesets.value = rulesetList
    if (!exits.value.some(item => item.tag === ruleTarget.value)) ruleTarget.value = 'direct'
    if (!exits.value.some(item => item.tag === rulesetTarget.value)) rulesetTarget.value = exits.value[0]?.tag || 'direct'
  } catch (cause) {
    error.value = cause instanceof Error ? cause.message : String(cause)
  } finally {
    loading.value = false
  }
}

async function login() {
  token.value = tokenInput.value.trim()
  if (!token.value) return
  localStorage.setItem('pdg-admin-token', token.value)
  await loadAll()
}

function logout() {
  if (runtimeTimer) window.clearInterval(runtimeTimer)
  runtimeTimer = undefined
  localStorage.removeItem('pdg-admin-token')
  token.value = ''
  tokenInput.value = ''
  overview.value = null
}

async function previewExit() {
  error.value = ''
  try {
    preview.value = await api<Preview>('/api/v1/exits/preview', {
      method: 'POST', body: JSON.stringify({ link: link.value.trim() }),
    })
  } catch (cause) {
    error.value = cause instanceof Error ? cause.message : String(cause)
  }
}

async function addExit() {
  loading.value = true
  error.value = ''
  try {
    await api('/api/v1/exits', { method: 'POST', body: JSON.stringify({ link: link.value.trim() }) })
    showAdd.value = false
    link.value = ''
    preview.value = null
    flash('出口已应用')
    await loadAll()
  } catch (cause) {
    error.value = cause instanceof Error ? cause.message : String(cause)
  } finally {
    loading.value = false
  }
}

async function setFinal(tag: string) {
  error.value = ''
  try {
    await api('/api/v1/final', { method: 'PUT', body: JSON.stringify({ tag }) })
    flash(`默认出口已切换为 ${tag}`)
    await loadAll()
  } catch (cause) {
    error.value = cause instanceof Error ? cause.message : String(cause)
  }
}

async function removeExit(item: Exit) {
  error.value = ''
  try {
    const impact = await api<{ groups: string[]; rules: string[]; final: boolean; telegram: boolean }>(
      `/api/v1/exits/${encodeURIComponent(item.tag)}/impact`,
    )
    const details = [
      impact.final ? '默认出口将自动切换' : '',
      impact.groups.length ? `影响故障组：${impact.groups.join('、')}` : '',
      impact.rules.length ? `迁移 ${impact.rules.length} 条分流引用` : '',
      impact.telegram ? 'Telegram 专用出口将跟随默认出口' : '',
    ].filter(Boolean).join('\n')
    if (!window.confirm(`删除出口 ${item.tag}？\n${details || '没有发现配置引用'}`)) return
    await api(`/api/v1/exits/${encodeURIComponent(item.tag)}`, { method: 'DELETE' })
    flash(`已删除 ${item.tag}`)
    await loadAll()
  } catch (cause) {
    error.value = cause instanceof Error ? cause.message : String(cause)
  }
}

async function testExits() {
  testing.value = true
  error.value = ''
  try {
    const result = await api<DelayResult[]>('/api/v1/exits/test', { method: 'POST', body: '{}' })
    delays.value = Object.fromEntries(result.map(item => [item.tag, item]))
  } catch (cause) {
    error.value = cause instanceof Error ? cause.message : String(cause)
  } finally {
    testing.value = false
  }
}

async function saveRule() {
  error.value = ''
  try {
    await api('/api/v1/rules', {
      method: 'POST', body: JSON.stringify({ domain: ruleDomain.value.trim(), target: ruleTarget.value }),
    })
    flash('分流规则已保存')
    ruleDomain.value = ''
    await loadAll()
  } catch (cause) {
    error.value = cause instanceof Error ? cause.message : String(cause)
  }
}

async function removeRule(item: Rule) {
  if (item.kind === 'ruleset') return
  if (!window.confirm(`删除 ${item.label} 的分流规则？`)) return
  error.value = ''
  try {
    await api(`/api/v1/rules/${encodeURIComponent(item.value)}`, { method: 'DELETE' })
    flash('规则已删除')
    await loadAll()
  } catch (cause) {
    error.value = cause instanceof Error ? cause.message : String(cause)
  }
}

function editGroup(item?: Exit) {
  groupName.value = item?.tag || ''
  groupMembers.value = item?.members ? [...item.members] : []
  editingGroup.value = Boolean(item)
  showGroup.value = true
}

async function saveGroup() {
  error.value = ''
  try {
    await api('/api/v1/groups', {
      method: 'POST', body: JSON.stringify({ name: groupName.value, members: groupMembers.value }),
    })
    showGroup.value = false
    editingGroup.value = false
    groupName.value = ''
    groupMembers.value = []
    flash('故障组已保存')
    await loadAll()
  } catch (cause) {
    error.value = cause instanceof Error ? cause.message : String(cause)
  }
}

async function testRoute() {
  error.value = ''
  routeResult.value = null
  try {
    routeResult.value = await api<RouteResult>('/api/v1/route/test', {
      method: 'POST', body: JSON.stringify({ domain: routeDomain.value }),
    })
  } catch (cause) {
    error.value = cause instanceof Error ? cause.message : String(cause)
  }
}

async function saveRuleset() {
  error.value = ''
  try {
    await api('/api/v1/rulesets', {
      method: 'POST',
      body: JSON.stringify({ url: rulesetUrl.value, target: rulesetTarget.value, label: rulesetLabel.value }),
    })
    rulesetUrl.value = ''
    rulesetLabel.value = ''
    flash('规则集已下载并应用')
    await loadAll()
  } catch (cause) {
    error.value = cause instanceof Error ? cause.message : String(cause)
  }
}

async function updateRuleset(item: Ruleset, target?: string) {
  const label = target === undefined ? window.prompt('规则集显示名称', item.label) : undefined
  if (target === undefined && label === null) return
  error.value = ''
  try {
    await api(`/api/v1/rulesets/${encodeURIComponent(item.tag)}`, {
      method: 'PUT', body: JSON.stringify(target === undefined ? { label } : { target }),
    })
    flash('规则集已更新')
    await loadAll()
  } catch (cause) {
    error.value = cause instanceof Error ? cause.message : String(cause)
  }
}

function rulesetTargetChange(item: Ruleset, event: Event) {
  updateRuleset(item, (event.target as HTMLSelectElement).value)
}

async function refreshRuleset(item: Ruleset) {
  error.value = ''
  try {
    await api(`/api/v1/rulesets/${encodeURIComponent(item.tag)}/refresh`, { method: 'POST', body: '{}' })
    flash(`${item.label} 已刷新`)
    await loadAll()
  } catch (cause) {
    error.value = cause instanceof Error ? cause.message : String(cause)
  }
}

async function removeRuleset(item: Ruleset) {
  if (!window.confirm(`删除规则集 ${item.label}？`)) return
  try {
    await api(`/api/v1/rulesets/${encodeURIComponent(item.tag)}`, { method: 'DELETE' })
    flash('规则集已删除')
    await loadAll()
  } catch (cause) {
    error.value = cause instanceof Error ? cause.message : String(cause)
  }
}

async function loadRuntime() {
  error.value = ''
  try {
    runtime.value = await api<RuntimeState>('/api/v1/connections')
  } catch (cause) {
    error.value = cause instanceof Error ? cause.message : String(cause)
  }
}

async function closeConnection(id?: string) {
  try {
    await api(id ? `/api/v1/connections/${encodeURIComponent(id)}` : '/api/v1/connections', { method: 'DELETE' })
    flash(id ? '连接已终止' : '全部连接已终止')
    await loadRuntime()
  } catch (cause) {
    error.value = cause instanceof Error ? cause.message : String(cause)
  }
}

async function loadLogs() {
  error.value = ''
  try {
    logs.value = (await api<{ lines: string[] }>('/api/v1/logs')).lines
  } catch (cause) {
    error.value = cause instanceof Error ? cause.message : String(cause)
  }
}

let runtimeTimer: number | undefined
async function selectPage(next: Page) {
  if (runtimeTimer) window.clearInterval(runtimeTimer)
  runtimeTimer = undefined
  page.value = next
  if (next === 'runtime') {
    await loadRuntime()
    runtimeTimer = window.setInterval(loadRuntime, 5000)
  }
  if (next === 'system') await loadLogs()
}

function formatBytes(value: number) {
  const units = ['B', 'KB', 'MB', 'GB', 'TB']
  let current = value || 0
  let index = 0
  while (current >= 1024 && index < units.length - 1) {
    current /= 1024
    index += 1
  }
  return `${current.toFixed(index ? 1 : 0)} ${units[index]}`
}

function serviceActive(value: string) {
  return value === 'active'
}

onMounted(loadAll)
onBeforeUnmount(() => {
  if (runtimeTimer) window.clearInterval(runtimeTimer)
})
</script>

<template>
  <main v-if="!token" class="login-shell">
    <section class="login-card">
      <div class="brand-mark">PDG</div>
      <p class="eyebrow">PRIVDNS GATEWAY</p>
      <h1>网关管理端</h1>
      <p class="muted">仅允许内网卡来源访问。输入终端或 Telegram Bot 提供的管理令牌。</p>
      <form @submit.prevent="login">
        <label for="token">管理令牌</label>
        <input id="token" v-model="tokenInput" type="password" autocomplete="current-password" placeholder="粘贴 admin token" />
        <button class="primary wide" type="submit">连接网关</button>
      </form>
      <p v-if="error" class="error-message">{{ error }}</p>
    </section>
  </main>

  <div v-else class="app-shell">
    <aside class="sidebar">
      <div class="brand-row">
        <div class="brand-mark small">PDG</div>
        <div><strong>PrivDNS</strong><span>Gateway</span></div>
      </div>
      <nav>
        <button v-for="item in navItems" :key="item.id" :class="{ active: page === item.id }" @click="selectPage(item.id)">
          <span>{{ item.icon }}</span>{{ item.label }}
        </button>
      </nav>
      <button class="logout" @click="logout">退出管理端</button>
    </aside>

    <section class="content">
      <header class="topbar">
        <div>
          <p class="eyebrow">PRIVDNS GATEWAY</p>
          <h1>{{ navItems.find(item => item.id === page)?.label }}</h1>
        </div>
        <button class="icon-button" :disabled="loading" title="刷新" @click="loadAll">↻</button>
      </header>

      <div v-if="error" class="banner error-message"><span>{{ error }}</span><button @click="error = ''">×</button></div>
      <div v-if="notice" class="toast">{{ notice }}</div>

      <template v-if="page === 'overview' && overview">
        <section class="hero-card">
          <div>
            <p class="eyebrow">DEFAULT ROUTE</p>
            <h2>{{ overview.default_exit || '未设置' }}</h2>
            <p class="muted">未命中显式分流规则的国际流量</p>
          </div>
          <div class="pulse" :class="{ down: Object.values(overview.services).some(value => value !== 'active') }"></div>
        </section>
        <section class="metric-grid">
          <article><span>代理出口</span><strong>{{ overview.proxy_count }}</strong></article>
          <article><span>故障组</span><strong>{{ overview.group_count }}</strong></article>
          <article><span>分流规则</span><strong>{{ overview.rule_count }}</strong></article>
        </section>
        <section class="panel">
          <div class="section-title"><div><p class="eyebrow">SERVICES</p><h2>服务状态</h2></div></div>
          <div class="service-list">
            <div v-for="(value, name) in overview.services" :key="name">
              <span class="status-dot" :class="{ online: serviceActive(value) }"></span>
              <strong>{{ name }}</strong><span class="muted">{{ value }}</span>
            </div>
          </div>
        </section>
      </template>

      <template v-if="page === 'exits'">
        <div class="section-actions">
          <button class="secondary" :disabled="testing" @click="testExits">{{ testing ? '测速中…' : '批量测速' }}</button>
          <button class="secondary" @click="editGroup()">＋ 故障组</button>
          <button class="primary" @click="showAdd = !showAdd; preview = null">＋ 添加出口</button>
        </div>
        <section v-if="showGroup" class="panel add-panel">
          <div class="section-title"><div><p class="eyebrow">FAILOVER GROUP</p><h2>故障切换组</h2></div></div>
          <div class="form-grid group-form">
            <input v-model="groupName" :disabled="editingGroup" placeholder="组名，例如 auto" />
            <div class="member-picker">
              <label v-for="item in concreteExits" :key="item.tag">
                <input v-model="groupMembers" type="checkbox" :value="item.tag" />
                <span>{{ item.tag }}</span>
              </label>
            </div>
            <button class="primary" @click="saveGroup">保存故障组</button>
          </div>
        </section>
        <section v-if="showAdd" class="panel add-panel">
          <div class="section-title"><div><p class="eyebrow">NEW OUTBOUND</p><h2>粘贴节点链接</h2></div></div>
          <textarea v-model="link" rows="4" placeholder="ss://、vless://、trojan://、hysteria2:// …"></textarea>
          <div v-if="preview" class="preview-card">
            <div><span>名称</span><strong>{{ preview.tag }}</strong></div>
            <div><span>协议</span><strong>{{ preview.type }}</strong></div>
            <div><span>地址</span><strong>{{ preview.server }}:{{ preview.server_port }}</strong></div>
            <div><span>TLS</span><strong>{{ preview.tls ? '开启' : '关闭' }}</strong></div>
            <p v-if="preview.replacing" class="warning">同名出口已存在，确认后将替换。</p>
          </div>
          <div class="form-actions">
            <button class="secondary" @click="previewExit">解析预览</button>
            <button v-if="preview" class="primary" :disabled="loading" @click="addExit">确认应用</button>
          </div>
        </section>
        <section class="exit-grid">
          <article v-for="item in exits" :key="item.tag" class="exit-card" :class="{ selected: item.default }">
            <div class="exit-head">
              <div><span class="protocol">{{ item.type }}</span><h2>{{ item.tag }}</h2></div>
              <span v-if="item.default" class="badge">默认</span>
            </div>
            <p v-if="item.members.length" class="route-chain">{{ item.members.join(' → ') }}</p>
            <p v-else class="muted endpoint">{{ item.server || '本机直出' }}<template v-if="item.server_port">:{{ item.server_port }}</template></p>
            <div class="exit-meta">
              <span v-if="delays[item.tag]" :class="delays[item.tag].ok ? 'good' : 'bad'">
                {{ delays[item.tag].ok ? `${delays[item.tag].delay} ms` : '不可用' }}
              </span>
              <span>{{ item.references }} 个引用</span>
            </div>
            <div class="card-actions">
              <button v-if="!item.default" @click="setFinal(item.tag)">设为默认</button>
              <button v-if="item.type === 'urltest'" @click="editGroup(item)">编辑成员</button>
              <button v-if="item.deletable" class="danger" @click="removeExit(item)">删除</button>
            </div>
          </article>
        </section>
      </template>

      <template v-if="page === 'rules'">
        <section class="panel route-tester">
          <div><p class="eyebrow">ROUTE TEST</p><h2>查询域名最终出口</h2></div>
          <div class="route-test-form">
            <input v-model="routeDomain" placeholder="输入域名" @keyup.enter="testRoute" />
            <button class="secondary" @click="testRoute">测试</button>
          </div>
          <div v-if="routeResult" class="route-result">
            <span>{{ routeResult.domain }}</span><strong>{{ routeResult.target }}</strong><small>{{ routeResult.kind }} · {{ routeResult.match }}</small>
          </div>
        </section>
        <section class="panel rule-form">
          <div class="section-title"><div><p class="eyebrow">ROUTE RULE</p><h2>添加或调整域名分流</h2></div></div>
          <div class="form-grid">
            <input v-model="ruleDomain" placeholder="例如 netflix.com" @keyup.enter="saveRule" />
            <select v-model="ruleTarget">
              <option value="direct">direct · 直连</option>
              <option v-for="item in exits" :key="item.tag" :value="item.tag">{{ item.tag }} · {{ item.type }}</option>
            </select>
            <button class="primary" @click="saveRule">保存规则</button>
          </div>
        </section>
        <section class="panel">
          <div class="section-title rules-heading">
            <div><p class="eyebrow">POLICIES</p><h2>当前分流</h2></div>
            <input v-model="search" class="search" placeholder="搜索域名或出口" />
          </div>
          <div class="rule-list">
            <div v-for="item in filteredRules" :key="`${item.kind}-${item.value}-${item.target}`" class="rule-row">
              <div><span class="kind">{{ item.kind === 'ruleset' ? '规则集' : item.kind === 'direct' ? '直连' : '域名' }}</span><strong>{{ item.label }}</strong></div>
              <div class="rule-target"><span>→</span><strong>{{ item.target }}</strong></div>
              <span v-if="item.count" class="muted">{{ item.count }} 条</span>
              <button v-if="item.kind !== 'ruleset'" class="text-danger" @click="removeRule(item)">删除</button>
            </div>
            <p v-if="!filteredRules.length" class="empty">没有匹配的分流规则</p>
          </div>
        </section>
        <section class="panel">
          <div class="section-title"><div><p class="eyebrow">RULE SETS</p><h2>远程规则集</h2></div></div>
          <div class="ruleset-form">
            <input v-model="rulesetUrl" placeholder="https://example.com/media.list" />
            <input v-model="rulesetLabel" placeholder="显示名称（可选）" />
            <select v-model="rulesetTarget">
              <option v-for="item in exits" :key="item.tag" :value="item.tag">{{ item.tag }}</option>
            </select>
            <button class="primary" @click="saveRuleset">下载并应用</button>
          </div>
          <div class="ruleset-list">
            <div v-for="item in rulesets" :key="item.tag" class="ruleset-row">
              <div><span class="kind">{{ item.format }}</span><strong>{{ item.label }}</strong><small>{{ item.count === null ? '二进制' : `${item.count} 条` }} · {{ item.available ? '可用' : '文件缺失' }}</small></div>
              <select :value="item.target" @change="rulesetTargetChange(item, $event)">
                <option v-for="exit in exits" :key="exit.tag" :value="exit.tag">{{ exit.tag }}</option>
              </select>
              <div class="row-actions">
                <button @click="updateRuleset(item)">改名</button><button @click="refreshRuleset(item)">刷新</button><button class="text-danger" @click="removeRuleset(item)">删除</button>
              </div>
            </div>
            <p v-if="!rulesets.length" class="empty">尚未添加规则集</p>
          </div>
        </section>
      </template>

      <template v-if="page === 'runtime'">
        <div class="section-actions runtime-actions">
          <button class="secondary" @click="loadRuntime">刷新连接</button>
          <button class="danger-button" @click="closeConnection()">全部断开</button>
        </div>
        <section v-if="runtime" class="metric-grid runtime-metrics">
          <article><span>活动连接</span><strong>{{ runtime.connections.length }}</strong></article>
          <article><span>会话上传</span><strong>{{ formatBytes(runtime.upload_total) }}</strong></article>
          <article><span>会话下载</span><strong>{{ formatBytes(runtime.download_total) }}</strong></article>
        </section>
        <section class="panel connection-list">
          <div v-for="item in runtime?.connections || []" :key="item.id" class="connection-row">
            <div><strong>{{ item.host }}</strong><span>{{ item.network || '?' }} · {{ item.source || '本机' }}</span></div>
            <div class="chain">{{ item.chains.join(' → ') || '未知出口' }}</div>
            <div class="bytes">↑ {{ formatBytes(item.upload) }}<br />↓ {{ formatBytes(item.download) }}</div>
            <button class="text-danger" @click="closeConnection(item.id)">断开</button>
          </div>
          <p v-if="runtime && !runtime.connections.length" class="empty">当前没有活动连接</p>
        </section>
      </template>

      <template v-if="page === 'system'">
        <section v-if="overview" class="panel">
          <div class="section-title"><div><p class="eyebrow">SYSTEM</p><h2>服务状态</h2></div></div>
          <div class="service-list">
            <div v-for="(value, name) in overview.services" :key="name">
              <span class="status-dot" :class="{ online: serviceActive(value) }"></span><strong>{{ name }}</strong><span class="muted">{{ value }}</span>
            </div>
          </div>
        </section>
        <section class="panel log-panel">
          <div class="section-title"><div><p class="eyebrow">JOURNAL</p><h2>最近日志</h2></div><button class="secondary" @click="loadLogs">刷新</button></div>
          <pre>{{ logs.join('\n') || '暂无日志' }}</pre>
        </section>
        <section class="system-actions">
          <button class="secondary" @click="loadAll">刷新全部状态</button>
          <button class="danger-button" @click="logout">退出并清除本机令牌</button>
        </section>
      </template>
    </section>

    <nav class="mobile-nav">
      <button v-for="item in navItems" :key="item.id" :class="{ active: page === item.id }" @click="selectPage(item.id)">
        <span>{{ item.icon }}</span>{{ item.label }}
      </button>
    </nav>
  </div>
</template>
