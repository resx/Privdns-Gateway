<script setup lang="ts">
import { computed, onBeforeUnmount, onMounted, ref, watch } from 'vue'
import {
  Activity, ChevronDown, ChevronRight, ChevronsUpDown, Database, Gauge, House,
  ListTree, Network, Pencil, Pin, Plus, RefreshCw, Route, Search, Server,
  Settings, Trash2, X,
} from '@lucide/vue'

type Page = 'overview' | 'nodes' | 'rules' | 'resources' | 'runtime' | 'system'

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
  source: 'subscription' | 'manual' | 'system'
  subscription_id: string | null
  subscription_label: string | null
  source_group: string | null
  server: string | null
  server_port: number | null
  tls: boolean
  members: string[]
  mode: 'auto' | 'manual' | null
  selected: string | null
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
  order: number
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
  target: string
  error: string | null
  elapsed?: number
}
interface SubscriptionOverrides {
  types: string[]
  rename: { pattern: string; replacement: string }[]
  sort: 'source' | 'name'
  properties: Record<string, boolean>
}
interface Subscription {
  id: string
  label: string
  url: string
  has_secret: boolean
  include: string
  exclude: string
  group: string
  custom_label: boolean
  custom_group: boolean
  groups: { tag: string; label: string; count: number }[]
  categories: { name: string; pattern: string }[]
  overrides: SubscriptionOverrides
  count: number
  skipped: number
  updated_at: string | null
  last_error: string | null
}
interface SubscriptionPreview {
  id: string
  url_display: string
  label: string
  include: string
  exclude: string
  group: string
  count: number
  skipped: number
  added: string[]
  updated: string[]
  removed: string[]
  nodes: { tag: string; type: string; server: string; server_port: number }[]
  groups: { tag: string; label: string; count: number; master: boolean }[]
  categories: { name: string; pattern: string }[]
  overrides: SubscriptionOverrides
}
interface Ruleset {
  tag: string
  label: string
  url: string
  target: string
  format: string
  count: number | null
  available: boolean
  updated_at: string | null
  last_error: string | null
}
interface Resources {
  subscriptions: Subscription[]
  rulesets: Ruleset[]
  geosite: { available: boolean; updated_at: string | null; files: number }
  project: { current: string; latest: string | null; update_available: boolean }
}
interface OverridePreset {
  id: string
  name: string
  description: string
  include?: string
  exclude?: string
  categories?: string
  sort?: 'source' | 'name'
  tcpFastOpen?: boolean
  udpFragment?: boolean
}
interface RulesetPreset {
  name: string
  description: string
  url: string
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

function storedChoice<T extends string>(key: string, choices: readonly T[], fallback: T): T {
  const value = localStorage.getItem(key) as T | null
  return value && choices.includes(value) ? value : fallback
}

function storedList(key: string): string[] | null {
  const value = localStorage.getItem(key)
  if (value === null) return null
  try {
    const parsed = JSON.parse(value)
    return Array.isArray(parsed) && parsed.every(item => typeof item === 'string') ? parsed : []
  } catch {
    return []
  }
}

const fragmentToken = new URLSearchParams(location.hash.slice(1)).get('token') || ''
if (fragmentToken) {
  localStorage.setItem('pdg-admin-token', fragmentToken)
  history.replaceState(null, '', location.pathname + location.search)
}

const token = ref(localStorage.getItem('pdg-admin-token') || '')
const tokenInput = ref('')
const page = ref<Page>(storedChoice('pdg-page', ['overview', 'nodes', 'rules', 'resources', 'runtime', 'system'] as const, 'overview'))
const loading = ref(false)
const error = ref('')
const notice = ref('')
const overview = ref<Overview | null>(null)
const exits = ref<Exit[]>([])
const rules = ref<Rule[]>([])
const rulesets = ref<Ruleset[]>([])
const subscriptions = ref<Subscription[]>([])
const delays = ref<Record<string, DelayResult>>({})
const runtime = ref<RuntimeState | null>(null)
const logs = ref<string[]>([])
const testing = ref(false)
const showAdd = ref(false)
const link = ref('')
const preview = ref<Preview | null>(null)
const search = ref('')
const nodeSearch = ref('')
const nodeWorkspace = ref(storedChoice('pdg-node-workspace', ['groups', 'providers', 'nodes'] as const, 'groups'))
const nodeScope = ref('all')
const nodeStatusFilter = ref<'all' | 'available' | 'failed' | 'untested'>('all')
const nodeSourceFilter = ref('all')
const nodeSort = ref(storedChoice('pdg-node-sort', ['source', 'name', 'delay'] as const, 'source'))
const nodeView = ref(storedChoice('pdg-node-view', ['list', 'grid'] as const, 'list'))
const storedExpandedGroups = storedList('pdg-expanded-groups')
const expandedGroups = ref<string[]>(storedExpandedGroups || [])
const ruleWorkspace = ref(storedChoice('pdg-rule-workspace', ['rules', 'providers'] as const, 'rules'))
const ruleKindFilter = ref<'all' | Rule['kind']>('all')
const ruleTargetFilter = ref('all')
const ruleSort = ref(storedChoice('pdg-rule-sort', ['source', 'name', 'target'] as const, 'source'))
const showRouteTester = ref(false)
const showRuleComposer = ref(false)
const showRulesetComposer = ref(false)
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
const showSubscription = ref(false)
const editingSubscription = ref<Subscription | null>(null)
const subscriptionUrl = ref('')
const subscriptionLabel = ref('')
const subscriptionInclude = ref('')
const subscriptionExclude = ref('')
const subscriptionGroup = ref('')
const subscriptionCategories = ref('')
const subscriptionTypes = ref<string[]>([])
const subscriptionRename = ref('')
const subscriptionSort = ref<'source' | 'name'>('source')
const subscriptionTfo = ref(false)
const subscriptionUdpFragment = ref(false)
const subscriptionAdvanced = ref(false)
const subscriptionPreview = ref<SubscriptionPreview | null>(null)
const testTarget = ref('google')
const resources = ref<Resources | null>(null)
const resourceBusy = ref('')
const subscriptionPreviewInput = ref('')
const presetSubscriptionId = ref('')
const presetRulesetTarget = ref('')

watch(page, value => localStorage.setItem('pdg-page', value))
watch(nodeWorkspace, value => localStorage.setItem('pdg-node-workspace', value))
watch(nodeSort, value => localStorage.setItem('pdg-node-sort', value))
watch(nodeView, value => localStorage.setItem('pdg-node-view', value))
watch(ruleWorkspace, value => localStorage.setItem('pdg-rule-workspace', value))
watch(ruleSort, value => localStorage.setItem('pdg-rule-sort', value))
watch(expandedGroups, value => localStorage.setItem('pdg-expanded-groups', JSON.stringify(value)), { deep: true })

const concreteExits = computed(() => exits.value.filter(item => !item.members.length))
const strategyGroups = computed(() => exits.value.filter(item => item.members.length))
const activeNodeGroup = computed(() => strategyGroups.value.find(item => item.tag === nodeScope.value) || null)
const visibleGroups = computed(() => {
  const query = nodeSearch.value.trim().toLowerCase()
  if (!query) return strategyGroups.value
  return strategyGroups.value.filter(group => {
    if (group.tag.toLowerCase().includes(query)) return true
    return group.members.some(member => member.toLowerCase().includes(query))
  })
})
const allGroupsExpanded = computed(() => (
  visibleGroups.value.length > 0 && visibleGroups.value.every(group => expandedGroups.value.includes(group.tag))
))
const nodeSheetOpen = computed(() => showSubscription.value || showGroup.value || showAdd.value)
watch(nodeSheetOpen, value => document.body.classList.toggle('sheet-open', value))
const nodeHealth = computed(() => {
  const output = { available: 0, failed: 0, untested: 0 }
  for (const item of concreteExits.value) {
    const result = delays.value[item.tag]
    if (!result) output.untested += 1
    else if (result.ok) output.available += 1
    else output.failed += 1
  }
  return output
})
const visibleNodes = computed(() => {
  const allowed = activeNodeGroup.value ? new Set(activeNodeGroup.value.members) : null
  const query = nodeSearch.value.trim().toLowerCase()
  const output = concreteExits.value.filter(item => {
    if (allowed && !allowed.has(item.tag)) return false
    if (nodeSourceFilter.value !== 'all' && item.subscription_id !== nodeSourceFilter.value) return false
    const result = delays.value[item.tag]
    if (nodeStatusFilter.value === 'available' && !result?.ok) return false
    if (nodeStatusFilter.value === 'failed' && (!result || result.ok)) return false
    if (nodeStatusFilter.value === 'untested' && result) return false
    return !query || `${item.tag} ${item.type} ${item.server || ''} ${item.subscription_label || ''}`.toLowerCase().includes(query)
  })
  return sortNodeItems(output)
})
function sortNodeItems(items: Exit[]) {
  const output = [...items]
  if (nodeSort.value === 'name') output.sort((left, right) => left.tag.localeCompare(right.tag, 'zh-CN'))
  if (nodeSort.value === 'delay') output.sort((left, right) => {
    const leftDelay = delays.value[left.tag]?.ok ? delays.value[left.tag].delay ?? Number.MAX_SAFE_INTEGER : Number.MAX_SAFE_INTEGER
    const rightDelay = delays.value[right.tag]?.ok ? delays.value[right.tag].delay ?? Number.MAX_SAFE_INTEGER : Number.MAX_SAFE_INTEGER
    return leftDelay - rightDelay
  })
  return output
}

function nodesForGroup(group: Exit) {
  const members = new Set(group.members)
  return sortNodeItems(concreteExits.value.filter(item => members.has(item.tag)))
}

function nodesForSubscription(identifier: string) {
  return sortNodeItems(concreteExits.value.filter(item => item.subscription_id === identifier))
}

function isGroupExpanded(tag: string) {
  return expandedGroups.value.includes(tag)
}

function toggleGroup(tag: string) {
  expandedGroups.value = isGroupExpanded(tag)
    ? expandedGroups.value.filter(item => item !== tag)
    : [...expandedGroups.value, tag]
}

function toggleAllGroups() {
  const visible = new Set(visibleGroups.value.map(group => group.tag))
  expandedGroups.value = allGroupsExpanded.value
    ? expandedGroups.value.filter(tag => !visible.has(tag))
    : [...new Set([...expandedGroups.value, ...visible])]
}

function closeNodeSheets() {
  showSubscription.value = false
  showGroup.value = false
  showAdd.value = false
}

function openAddNode() {
  const opening = !showAdd.value
  closeNodeSheets()
  preview.value = null
  showAdd.value = opening
}

function delayTone(tag: string) {
  const result = delays.value[tag]
  if (!result) return 'untested'
  if (!result.ok) return 'failed'
  if ((result.delay || 0) < 200) return 'fast'
  if ((result.delay || 0) < 500) return 'medium'
  return 'slow'
}

function nodeNameParts(tag: string) {
  const match = tag.match(/^(\p{Regional_Indicator}{2})[-\s]*/u)
  return { flag: match?.[1] || '', name: match ? tag.slice(match[0].length) : tag }
}

function groupStatus(group: Exit) {
  const nodes = nodesForGroup(group)
  const available = nodes.filter(item => delays.value[item.tag]?.ok).length
  const failed = nodes.filter(item => delays.value[item.tag] && !delays.value[item.tag].ok).length
  return { available, failed, untested: nodes.length - available - failed }
}

function openGroupNodes(group: Exit) {
  nodeScope.value = group.tag
  nodeSourceFilter.value = 'all'
  nodeWorkspace.value = 'nodes'
}

function openSubscriptionNodes(item: Subscription) {
  nodeScope.value = 'all'
  nodeSourceFilter.value = item.id
  nodeWorkspace.value = 'nodes'
}

function openAllNodes() {
  nodeScope.value = 'all'
  nodeSourceFilter.value = 'all'
  nodeWorkspace.value = 'nodes'
}

const policyTargets = computed(() => {
  const counts = new Map<string, number>()
  for (const item of rules.value) counts.set(item.target, (counts.get(item.target) || 0) + 1)
  return [...counts.entries()].map(([target, count]) => ({ target, count }))
    .sort((left, right) => right.count - left.count || left.target.localeCompare(right.target, 'zh-CN'))
})
const ruleKindCounts = computed(() => ({
  domain: rules.value.filter(item => item.kind === 'domain').length,
  direct: rules.value.filter(item => item.kind === 'direct').length,
  ruleset: rules.value.filter(item => item.kind === 'ruleset').length,
}))
const filteredRules = computed(() => {
  const query = search.value.trim().toLowerCase()
  const output = rules.value.filter(item => {
    if (ruleKindFilter.value !== 'all' && item.kind !== ruleKindFilter.value) return false
    if (ruleTargetFilter.value !== 'all' && item.target !== ruleTargetFilter.value) return false
    return !query || `${item.label} ${item.target} ${item.kind}`.toLowerCase().includes(query)
  })
  if (ruleSort.value === 'name') output.sort((left, right) => left.label.localeCompare(right.label, 'zh-CN'))
  if (ruleSort.value === 'target') output.sort((left, right) => left.target.localeCompare(right.target, 'zh-CN'))
  if (ruleSort.value === 'source') output.sort((left, right) => left.order - right.order)
  return output
})

const navItems = [
  { id: 'overview' as Page, label: '概览', icon: House },
  { id: 'nodes' as Page, label: '节点', icon: Server },
  { id: 'rules' as Page, label: '分流', icon: Route },
  { id: 'resources' as Page, label: '资源', icon: Database },
  { id: 'runtime' as Page, label: '连接', icon: Activity },
  { id: 'system' as Page, label: '系统', icon: Settings },
]
const protocolOptions = ['shadowsocks', 'vmess', 'trojan', 'vless', 'hysteria', 'hysteria2', 'tuic', 'anytls', 'shadowtls', 'socks', 'http']
const overridePresets: OverridePreset[] = [
  {
    id: 'cleanup', name: '清理套餐信息', description: '过滤剩余流量、到期时间、官网和套餐说明等伪节点。',
    exclude: '剩余|流量|到期|过期|官网|套餐|Traffic|Expire|官网地址',
  },
  {
    id: 'regions', name: '常用地区分组', description: '自动生成香港、台湾、日本、新加坡、美国五个节点组。',
    categories: '香港=香港|港|HK|Hong Kong\n台湾=台湾|台|TW|Taiwan\n日本=日本|日|JP|Japan\n新加坡=新加坡|狮城|SG|Singapore\n美国=美国|美|US|United States',
  },
  {
    id: 'sort', name: '名称整理', description: '按节点名称排序，刷新订阅后顺序保持稳定。', sort: 'name',
  },
  {
    id: 'network', name: '网络优化', description: '开启 TCP Fast Open 和 UDP 分片；AnyTLS 会自动跳过不兼容的 TFO。',
    tcpFastOpen: true, udpFragment: true,
  },
]
const rulesetPresets: RulesetPreset[] = [
  { name: 'OpenAI', description: 'ChatGPT、OpenAI API 与相关域名', url: 'https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Surge/OpenAI/OpenAI.list' },
  { name: 'Telegram', description: 'Telegram 域名与 IP 网段', url: 'https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Surge/Telegram/Telegram.list' },
  { name: 'Netflix', description: 'Netflix 域名与流媒体 IP 网段', url: 'https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Surge/Netflix/Netflix.list' },
  { name: 'YouTube', description: 'YouTube 与 Google Video 相关域名', url: 'https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Surge/YouTube/YouTube.list' },
  { name: 'GitHub', description: 'GitHub、GitHub API 与静态资源域名', url: 'https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Surge/GitHub/GitHub.list' },
  { name: 'Apple 服务', description: 'Apple 中国区服务域名', url: 'https://raw.githubusercontent.com/DustinWin/ruleset_geodata/sing-box-ruleset/apple-cn.srs' },
  { name: 'Microsoft 服务', description: 'Microsoft 中国区服务域名', url: 'https://raw.githubusercontent.com/DustinWin/ruleset_geodata/sing-box-ruleset/microsoft-cn.srs' },
  { name: '游戏平台', description: '常用游戏平台及游戏下载域名', url: 'https://raw.githubusercontent.com/DustinWin/ruleset_geodata/sing-box-ruleset/games.srs' },
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
    const [summary, exitList, ruleList, rulesetList, subscriptionList] = await Promise.all([
      api<Overview>('/api/v1/overview'),
      api<Exit[]>('/api/v1/exits'),
      api<Rule[]>('/api/v1/rules'),
      api<Ruleset[]>('/api/v1/rulesets'),
      api<Subscription[]>('/api/v1/subscriptions'),
    ])
    overview.value = summary
    exits.value = exitList
    rules.value = ruleList
    rulesets.value = rulesetList
    subscriptions.value = subscriptionList
    if (!exits.value.some(item => item.tag === ruleTarget.value)) ruleTarget.value = 'direct'
    if (!exits.value.some(item => item.tag === rulesetTarget.value)) rulesetTarget.value = exits.value[0]?.tag || 'direct'
    if (!subscriptions.value.some(item => item.id === presetSubscriptionId.value)) presetSubscriptionId.value = subscriptions.value[0]?.id || ''
    if (!exits.value.some(item => item.tag === presetRulesetTarget.value)) presetRulesetTarget.value = overview.value?.default_exit || exits.value[0]?.tag || 'direct'
    if (nodeScope.value !== 'all' && !exitList.some(item => item.tag === nodeScope.value && item.members.length)) nodeScope.value = 'all'
    expandedGroups.value = expandedGroups.value.filter(tag => strategyGroups.value.some(group => group.tag === tag))
    if (storedExpandedGroups === null && !expandedGroups.value.length && strategyGroups.value.length) {
      const initial = strategyGroups.value.find(item => item.default) || strategyGroups.value[0]
      expandedGroups.value = initial ? [initial.tag] : []
    }
    if (ruleTargetFilter.value !== 'all' && !ruleList.some(item => item.target === ruleTargetFilter.value)) ruleTargetFilter.value = 'all'
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

function finalTargetChange(event: Event) {
  setFinal((event.target as HTMLSelectElement).value)
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

async function testExits(tags?: string[]) {
  testing.value = true
  error.value = ''
  try {
    const result = await api<DelayResult[]>('/api/v1/exits/test', {
      method: 'POST', body: JSON.stringify({ ...(tags ? { tags } : {}), target: testTarget.value }),
    })
    delays.value = { ...delays.value, ...Object.fromEntries(result.map(item => [item.tag, item])) }
  } catch (cause) {
    error.value = cause instanceof Error ? cause.message : String(cause)
  } finally {
    testing.value = false
  }
}

function categoryRules() {
  return subscriptionCategories.value.split('\n').map(line => line.trim()).filter(Boolean).map(line => {
    const separator = line.indexOf('=')
    return {
      name: separator >= 0 ? line.slice(0, separator).trim() : line,
      pattern: separator >= 0 ? line.slice(separator + 1).trim() : '',
    }
  })
}

function renameRules() {
  return subscriptionRename.value.split('\n').map(line => line.trim()).filter(Boolean).map(line => {
    const separator = line.indexOf('=>')
    return { pattern: separator >= 0 ? line.slice(0, separator).trim() : line, replacement: separator >= 0 ? line.slice(separator + 2).trim() : '' }
  })
}

function subscriptionPayload() {
  return {
    ...(subscriptionUrl.value.trim() ? { url: subscriptionUrl.value.trim() } : {}),
    label: subscriptionLabel.value.trim(),
    include: subscriptionInclude.value.trim(),
    exclude: subscriptionExclude.value.trim(),
    group: subscriptionGroup.value.trim(),
    categories: categoryRules(),
    overrides: {
      types: subscriptionTypes.value,
      rename: renameRules(),
      sort: subscriptionSort.value,
      properties: { tcp_fast_open: subscriptionTfo.value, udp_fragment: subscriptionUdpFragment.value },
    },
  }
}

function subscriptionInputKey() {
  return JSON.stringify(subscriptionPayload())
}

function editSubscription(item?: Subscription) {
  closeNodeSheets()
  editingSubscription.value = item || null
  subscriptionUrl.value = ''
  subscriptionLabel.value = item?.custom_label ? item.label : ''
  subscriptionInclude.value = item?.include || ''
  subscriptionExclude.value = item?.exclude || ''
  subscriptionGroup.value = item?.custom_group ? item.group : ''
  subscriptionCategories.value = (item?.categories || []).map(category => `${category.name}=${category.pattern}`).join('\n')
  subscriptionTypes.value = [...(item?.overrides?.types || [])]
  subscriptionRename.value = (item?.overrides?.rename || []).map(rule => `${rule.pattern} => ${rule.replacement}`).join('\n')
  subscriptionSort.value = item?.overrides?.sort || 'source'
  subscriptionTfo.value = item?.overrides?.properties?.tcp_fast_open || false
  subscriptionUdpFragment.value = item?.overrides?.properties?.udp_fragment || false
  subscriptionAdvanced.value = Boolean(item && (
    item.include || item.exclude || item.categories.length || item.custom_group
    || item.overrides.types.length || item.overrides.rename.length
    || item.overrides.sort !== 'source' || Object.values(item.overrides.properties).some(Boolean)
  ))
  subscriptionPreview.value = null
  subscriptionPreviewInput.value = ''
  showSubscription.value = true
}

async function previewNodeSubscription() {
  error.value = ''
  const payload = subscriptionPayload()
  if (!editingSubscription.value && !payload.url) {
    error.value = '请输入节点订阅 URL'
    return
  }
  try {
    const path = editingSubscription.value
      ? `/api/v1/subscriptions/${encodeURIComponent(editingSubscription.value.id)}/preview`
      : '/api/v1/subscriptions/preview'
    subscriptionPreview.value = await api<SubscriptionPreview>(path, {
      method: 'POST', body: JSON.stringify(payload),
    })
    subscriptionPreviewInput.value = subscriptionInputKey()
  } catch (cause) {
    error.value = cause instanceof Error ? cause.message : String(cause)
  }
}

async function saveNodeSubscription() {
  if (!subscriptionPreview.value || subscriptionPreviewInput.value !== subscriptionInputKey()) {
    error.value = '订阅参数已变化，请重新预览差异'
    return
  }
  loading.value = true
  error.value = ''
  try {
    const path = editingSubscription.value
      ? `/api/v1/subscriptions/${encodeURIComponent(editingSubscription.value.id)}`
      : '/api/v1/subscriptions'
    await api(path, { method: editingSubscription.value ? 'PUT' : 'POST', body: JSON.stringify(subscriptionPayload()) })
    showSubscription.value = false
    editingSubscription.value = null
    subscriptionPreview.value = null
    flash('节点订阅已应用')
    await loadAll()
  } catch (cause) {
    error.value = cause instanceof Error ? cause.message : String(cause)
  } finally {
    loading.value = false
  }
}

async function refreshNodeSubscription(item: Subscription) {
  error.value = ''
  try {
    await api(`/api/v1/subscriptions/${encodeURIComponent(item.id)}/refresh`, { method: 'POST', body: '{}' })
    flash(`${item.label} 已刷新`)
    await loadAll()
  } catch (cause) {
    error.value = cause instanceof Error ? cause.message : String(cause)
  }
}

async function refreshAllSubscriptions() {
  error.value = ''
  try {
    const result = await api<{ id: string; ok: boolean; error?: string }[]>('/api/v1/subscriptions/refresh', {
      method: 'POST', body: '{}',
    })
    const failed = result.filter(item => !item.ok)
    flash(failed.length ? `${result.length - failed.length} 个成功，${failed.length} 个失败` : `已刷新 ${result.length} 个订阅`)
    if (failed.length) error.value = failed.map(item => item.error || item.id).join('；')
    await loadAll()
  } catch (cause) {
    error.value = cause instanceof Error ? cause.message : String(cause)
  }
}

async function removeNodeSubscription(item: Subscription) {
  if (!window.confirm(`删除节点订阅 ${item.label}？\n将删除其 ${item.count} 个节点和分类组，引用会迁移到可用出口。`)) return
  error.value = ''
  try {
    await api(`/api/v1/subscriptions/${encodeURIComponent(item.id)}`, { method: 'DELETE' })
    flash(`${item.label} 已删除`)
    await loadAll()
  } catch (cause) {
    error.value = cause instanceof Error ? cause.message : String(cause)
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
  closeNodeSheets()
  groupName.value = item?.tag || ''
  groupMembers.value = item?.members ? [...item.members] : []
  editingGroup.value = Boolean(item)
  showGroup.value = true
}

function groupSelectionChange(item: Exit, event: Event) {
  setGroupSelection(item, (event.target as HTMLSelectElement).value)
}

async function setGroupSelection(item: Exit, selected: string) {
  error.value = ''
  try {
    await api(`/api/v1/groups/${encodeURIComponent(item.tag)}/selection`, {
      method: 'PUT', body: JSON.stringify({ selected: selected || null }),
    })
    flash(selected ? `${item.tag} 已固定到 ${selected}` : `${item.tag} 已恢复自动优选`)
    await loadAll()
  } catch (cause) {
    error.value = cause instanceof Error ? cause.message : String(cause)
  }
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

function ruleTargetChange(item: Rule, event: Event) {
  saveExistingRule(item, (event.target as HTMLSelectElement).value)
}

async function saveExistingRule(item: Rule, target: string) {
  error.value = ''
  try {
    await api('/api/v1/rules', {
      method: 'POST', body: JSON.stringify({ domain: item.value, target }),
    })
    flash(`${item.label} → ${target}`)
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

async function loadResources() {
  error.value = ''
  try {
    resources.value = await api<Resources>('/api/v1/resources')
  } catch (cause) {
    error.value = cause instanceof Error ? cause.message : String(cause)
  }
}

async function applyOverridePreset(preset: OverridePreset) {
  const subscription = subscriptions.value.find(item => item.id === presetSubscriptionId.value)
  if (!subscription) {
    error.value = '请先添加并选择一个节点订阅'
    return
  }
  editSubscription(subscription)
  if (preset.include) subscriptionInclude.value = preset.include
  if (preset.exclude) {
    subscriptionExclude.value = subscriptionExclude.value
      ? `(?:${subscriptionExclude.value})|(?:${preset.exclude})`
      : preset.exclude
  }
  if (preset.categories) {
    const currentNames = new Set(categoryRules().map(item => item.name))
    const additions = preset.categories.split('\n').filter(line => !currentNames.has(line.split('=', 1)[0]))
    subscriptionCategories.value = [subscriptionCategories.value, ...additions].filter(Boolean).join('\n')
  }
  if (preset.sort) subscriptionSort.value = preset.sort
  if (preset.tcpFastOpen) subscriptionTfo.value = true
  if (preset.udpFragment) subscriptionUdpFragment.value = true
  subscriptionAdvanced.value = true
  page.value = 'nodes'
  await previewNodeSubscription()
  if (subscriptionPreview.value) flash(`已套用“${preset.name}”，确认差异后再应用`)
}

async function installRulesetPreset(preset: RulesetPreset) {
  if (!presetRulesetTarget.value) {
    error.value = '请选择规则集使用的出口'
    return
  }
  resourceBusy.value = `preset-${preset.name}`
  error.value = ''
  try {
    await api('/api/v1/rulesets', {
      method: 'POST',
      body: JSON.stringify({ url: preset.url, target: presetRulesetTarget.value, label: preset.name }),
    })
    flash(`${preset.name} 规则集已安装`)
    await Promise.all([loadAll(), loadResources()])
  } catch (cause) {
    error.value = cause instanceof Error ? cause.message : String(cause)
  } finally {
    resourceBusy.value = ''
  }
}

async function refreshResource(kind: 'subscriptions' | 'rulesets' | 'geosite') {
  resourceBusy.value = kind
  error.value = ''
  try {
    const path = kind === 'subscriptions' ? '/api/v1/subscriptions/refresh' : kind === 'rulesets' ? '/api/v1/rulesets/refresh' : '/api/v1/resources/geosite/refresh'
    const result = await api<{ ok?: boolean; error?: string }[] | { ok: boolean }>(path, { method: 'POST', body: '{}' })
    const failed = Array.isArray(result) ? result.filter(item => !item.ok) : []
    const label = kind === 'subscriptions' ? '节点订阅' : kind === 'rulesets' ? '远程规则集' : 'Geosite'
    flash(failed.length ? `${label}：${failed.length} 个刷新失败` : `${label} 已刷新`)
    if (failed.length) error.value = failed.map(item => item.error || '刷新失败').join('；')
    await Promise.all([loadAll(), loadResources()])
  } catch (cause) {
    error.value = cause instanceof Error ? cause.message : String(cause)
  } finally {
    resourceBusy.value = ''
  }
}

async function checkProjectUpdate() {
  resourceBusy.value = 'project'
  try {
    const project = await api<Resources['project']>('/api/v1/resources/project/check', { method: 'POST', body: '{}' })
    if (resources.value) resources.value.project = project
    flash(project.update_available ? `发现新版本 ${project.latest}` : '当前已是最新版本')
  } catch (cause) {
    error.value = cause instanceof Error ? cause.message : String(cause)
  } finally {
    resourceBusy.value = ''
  }
}

async function startProjectUpdate() {
  if (!window.confirm('确认后台执行 pdg update？服务会短暂重启，失败将自动回滚。')) return
  try {
    await api('/api/v1/resources/project/update', { method: 'POST', body: '{}' })
    flash('更新任务已启动，请稍后重新连接')
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
  closeNodeSheets()
  if (runtimeTimer) window.clearInterval(runtimeTimer)
  runtimeTimer = undefined
  page.value = next
  if (next === 'runtime') {
    await loadRuntime()
    runtimeTimer = window.setInterval(loadRuntime, 5000)
  }
  if (next === 'resources') await loadResources()
  if (next === 'system') await loadLogs()
}

function formatTime(value?: string | null) {
  if (!value) return '尚未更新'
  const date = new Date(value)
  return Number.isNaN(date.getTime()) ? value : date.toLocaleString('zh-CN', { hour12: false })
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

function handleGlobalKeydown(event: KeyboardEvent) {
  if (event.key === 'Escape' && nodeSheetOpen.value) closeNodeSheets()
}

onMounted(() => {
  window.addEventListener('keydown', handleGlobalKeydown)
  loadAll()
})
onBeforeUnmount(() => {
  if (runtimeTimer) window.clearInterval(runtimeTimer)
  window.removeEventListener('keydown', handleGlobalKeydown)
  document.body.classList.remove('sheet-open')
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
          <component :is="item.icon" :size="19" />{{ item.label }}
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
        <button class="icon-button" :disabled="loading" title="刷新" @click="loadAll"><RefreshCw :size="19" /></button>
      </header>

      <div v-if="error" class="banner error-message"><span>{{ error }}</span><button @click="error = ''">×</button></div>
      <div v-if="notice" class="toast">{{ notice }}</div>

      <template v-if="page === 'overview' && overview">
        <section class="hero-card">
          <div>
            <p class="eyebrow">DEFAULT ROUTE</p>
            <h2>{{ overview.default_exit || '未设置' }}</h2>
            <p class="muted">未命中显式分流规则的国际流量</p>
            <select class="quick-final" :value="overview.default_exit" @change="finalTargetChange">
              <option v-for="item in exits" :key="item.tag" :value="item.tag">{{ item.tag }} · {{ item.type }}</option>
            </select>
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

      <template v-if="page === 'nodes'">
        <div class="section-actions node-actions">
          <select v-model="testTarget" class="target-select" aria-label="测速目标">
            <option value="google">Google 204</option><option value="cloudflare">Cloudflare 204</option><option value="apple">Apple</option>
          </select>
          <button class="secondary batch-test" :disabled="testing" title="批量测试全部节点" @click="testExits()"><Gauge :size="17" /><span>{{ testing ? '测速中…' : '批量测速' }}</span></button>
          <button class="secondary" title="添加或管理节点订阅" @click="editSubscription()"><Database :size="17" /><span>添加订阅</span></button>
          <button class="secondary" title="创建节点策略组" @click="editGroup()"><Network :size="17" /><span>节点组</span></button>
          <button class="primary" title="粘贴单个节点链接" @click="openAddNode"><Plus :size="17" /><span>添加节点</span></button>
        </div>
        <div v-if="nodeSheetOpen" class="sheet-backdrop" @click="closeNodeSheets"></div>
        <section class="workspace-switcher">
          <div class="segmented-control">
            <button :class="{ active: nodeWorkspace === 'groups' }" title="策略组" @click="nodeWorkspace = 'groups'; nodeScope = 'all'">策略组 <span>{{ strategyGroups.length }}</span></button>
            <button :class="{ active: nodeWorkspace === 'providers' }" title="订阅来源" @click="nodeWorkspace = 'providers'">订阅 <span>{{ subscriptions.length }}</span></button>
            <button :class="{ active: nodeWorkspace === 'nodes' }" title="全部节点" @click="openAllNodes">节点 <span>{{ concreteExits.length }}</span></button>
          </div>
          <div class="health-summary">
            <button class="fast" @click="nodeStatusFilter = 'available'; openAllNodes()">可用 {{ nodeHealth.available }}</button>
            <button class="failed" @click="nodeStatusFilter = 'failed'; openAllNodes()">失败 {{ nodeHealth.failed }}</button>
            <button class="untested" @click="nodeStatusFilter = 'untested'; openAllNodes()">未测 {{ nodeHealth.untested }}</button>
          </div>
        </section>
        <section v-if="showSubscription" class="panel add-panel node-sheet">
          <div class="section-title sheet-title">
            <div><p class="eyebrow">NODE SUBSCRIPTION</p><h2>{{ editingSubscription ? `编辑 ${editingSubscription.label}` : '添加节点订阅' }}</h2></div>
            <button class="icon-button sheet-close" title="关闭" @click="showSubscription = false"><X :size="18" /></button>
          </div>
          <div class="subscription-form">
            <div class="subscription-basic">
              <input v-model="subscriptionUrl" type="url" :placeholder="editingSubscription ? '新的完整订阅 URL（留空保留当前地址）' : '完整订阅 URL，例如 https://example.com/sub?token=…&amp;client=sing-box'" />
              <input v-model="subscriptionLabel" placeholder="订阅名称（可选）" />
            </div>
            <button class="secondary advanced-toggle" :aria-expanded="subscriptionAdvanced" @click="subscriptionAdvanced = !subscriptionAdvanced">
              <Settings :size="16" />{{ subscriptionAdvanced ? '收起高级设置' : '高级设置' }}
            </button>
            <div v-if="subscriptionAdvanced" class="subscription-advanced">
              <input v-model="subscriptionGroup" placeholder="分类组名称（留空自动生成）" />
              <input v-model="subscriptionInclude" placeholder="仅保留名称匹配，例如 香港|HK" />
              <input v-model="subscriptionExclude" placeholder="排除名称匹配，例如 过期|剩余流量" />
              <textarea v-model="subscriptionCategories" rows="3" placeholder="附加分类，每行 名称=正则，例如：&#10;🇭🇰 香港=香港|HK&#10;🇹🇼 台湾=台湾|TW"></textarea>
              <fieldset class="override-box">
                <legend>结构化覆写</legend>
                <div class="protocol-picker">
                  <label v-for="protocol in protocolOptions" :key="protocol"><input v-model="subscriptionTypes" type="checkbox" :value="protocol" />{{ protocol }}</label>
                </div>
                <textarea v-model="subscriptionRename" rows="3" placeholder="正则重命名，每行 匹配 => 替换，例如：^(HK)- => 🇭🇰 香港-$1-"></textarea>
                <div class="override-options">
                  <label>排序<select v-model="subscriptionSort"><option value="source">订阅原序</option><option value="name">按名称</option></select></label>
                  <label class="switch-row"><input v-model="subscriptionTfo" type="checkbox" />TCP Fast Open</label>
                  <label class="switch-row"><input v-model="subscriptionUdpFragment" type="checkbox" />UDP 分片</label>
                </div>
              </fieldset>
            </div>
          </div>
          <div v-if="subscriptionPreview" class="subscription-preview">
            <div><span>可用节点</span><strong>{{ subscriptionPreview.count }}</strong></div>
            <div><span>新增</span><strong>{{ subscriptionPreview.added.length }}</strong></div>
            <div><span>更新</span><strong>{{ subscriptionPreview.updated.length }}</strong></div>
            <div><span>移除</span><strong>{{ subscriptionPreview.removed.length }}</strong></div>
            <p>主分类组 <strong>{{ subscriptionPreview.group }}</strong><template v-if="subscriptionPreview.skipped">，跳过 {{ subscriptionPreview.skipped }} 项</template></p>
            <p v-if="subscriptionPreview.groups.length > 1" class="muted">附加分类：{{ subscriptionPreview.groups.slice(1).map(item => `${item.label} ${item.count}`).join('、') }}</p>
            <p class="muted">覆写：{{ subscriptionPreview.overrides.types.length ? subscriptionPreview.overrides.types.join('、') : '全部协议' }} · {{ subscriptionPreview.overrides.sort === 'name' ? '名称排序' : '原序' }} · {{ subscriptionPreview.overrides.rename.length }} 条重命名</p>
            <p class="muted node-preview">{{ subscriptionPreview.nodes.map(item => `${item.tag} · ${item.type}`).join('、') }}</p>
          </div>
          <div class="form-actions">
            <button class="secondary" @click="previewNodeSubscription">下载并预览差异</button>
            <button v-if="subscriptionPreview" class="primary" :disabled="loading" @click="saveNodeSubscription">确认应用</button>
          </div>
        </section>
        <section v-if="nodeWorkspace === 'providers'" class="panel subscription-panel">
          <div class="section-title">
            <div><p class="eyebrow">SUBSCRIPTIONS</p><h2>节点订阅</h2></div>
            <button class="secondary" :disabled="!subscriptions.length" @click="refreshAllSubscriptions">全部刷新</button>
          </div>
          <p v-if="!subscriptions.length" class="empty-state">尚未添加节点订阅</p>
          <div v-else class="provider-grid">
            <article v-for="item in subscriptions" :key="item.id" class="provider-card" :class="{ degraded: item.last_error }">
              <div class="provider-head">
                <div><span class="kind">{{ item.last_error ? '刷新异常' : '订阅可用' }}</span><h3>{{ item.label }}</h3><small>{{ item.url }}</small></div>
                <div class="provider-count"><strong>{{ item.count }}</strong><span>节点</span></div>
              </div>
              <div class="provider-meta">
                <span>{{ item.groups.length }} 个策略组</span><span v-if="item.skipped">跳过 {{ item.skipped }}</span><span>{{ formatTime(item.updated_at) }}</span>
              </div>
              <p v-if="item.last_error" class="bad provider-error">{{ item.last_error }}</p>
              <div class="provider-node-preview">
                <button v-for="node in nodesForSubscription(item.id).slice(0, 12)" :key="node.tag" :class="delayTone(node.tag)" @click="openSubscriptionNodes(item)">
                  <span v-if="nodeNameParts(node.tag).flag" class="node-flag">{{ nodeNameParts(node.tag).flag }}</span>{{ nodeNameParts(node.tag).name }}
                </button>
                <span v-if="nodesForSubscription(item.id).length > 12">+{{ nodesForSubscription(item.id).length - 12 }}</span>
              </div>
              <div class="provider-actions">
                <button @click="openSubscriptionNodes(item)">查看节点</button>
                <button @click="refreshNodeSubscription(item)">刷新</button>
                <button @click="editSubscription(item)">配置</button>
                <button class="text-danger" @click="removeNodeSubscription(item)">删除</button>
              </div>
            </article>
          </div>
        </section>
        <section v-if="showGroup" class="panel add-panel node-sheet">
          <div class="section-title sheet-title"><div><p class="eyebrow">FAILOVER GROUP</p><h2>故障切换组</h2></div><button class="icon-button sheet-close" title="关闭" @click="showGroup = false"><X :size="18" /></button></div>
          <div class="form-grid group-form">
            <input v-model="groupName" :disabled="editingGroup" placeholder="组名，例如 自动优选、日本节点、Global" />
            <div class="member-picker">
              <label v-for="item in concreteExits" :key="item.tag">
                <input v-model="groupMembers" type="checkbox" :value="item.tag" />
                <span>{{ item.tag }}</span>
              </label>
            </div>
            <button class="primary" @click="saveGroup">保存故障组</button>
          </div>
        </section>
        <section v-if="showAdd" class="panel add-panel node-sheet">
          <div class="section-title sheet-title"><div><p class="eyebrow">NEW OUTBOUND</p><h2>粘贴节点链接</h2></div><button class="icon-button sheet-close" title="关闭" @click="showAdd = false"><X :size="18" /></button></div>
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
        <section v-if="nodeWorkspace === 'groups'" class="group-dashboard">
          <div class="workspace-toolbar">
            <div><p class="eyebrow">POLICY GROUPS</p><h2>策略组总览 <span>{{ visibleGroups.length }}</span></h2></div>
            <div class="node-tools">
              <input v-model="nodeSearch" class="search" placeholder="搜索策略组或节点" />
              <select v-model="nodeSort"><option value="source">配置顺序</option><option value="name">名称排序</option><option value="delay">延迟排序</option></select>
              <button class="secondary compact" :disabled="testing" title="测试全部可见节点" @click="testExits(concreteExits.map(item => item.tag))"><Gauge :size="15" /><span>全部测速</span></button>
              <button class="secondary compact" :title="allGroupsExpanded ? '收起全部策略组' : '展开全部策略组'" @click="toggleAllGroups"><ChevronsUpDown :size="15" /><span>{{ allGroupsExpanded ? '全部收起' : '全部展开' }}</span></button>
            </div>
          </div>
          <div class="policy-group-grid">
            <article v-for="group in visibleGroups" :key="group.tag" class="policy-group-card" :class="{ selected: group.default }">
              <div class="policy-group-head">
                <button class="group-expand" :title="isGroupExpanded(group.tag) ? '收起' : '展开'" @click="toggleGroup(group.tag)">
                  <ChevronDown v-if="isGroupExpanded(group.tag)" :size="17" /><ChevronRight v-else :size="17" />
                </button>
                <div class="group-title"><span class="kind">{{ group.mode === 'manual' ? 'SELECTOR' : 'URLTEST' }}</span><h3>{{ group.tag }}</h3></div>
                <span v-if="group.default" class="badge">默认</span>
                <div class="group-health">
                  <span class="fast" title="可用节点">{{ groupStatus(group).available }}</span><span class="failed" title="失败节点">{{ groupStatus(group).failed }}</span><span class="untested" title="未测速节点">{{ groupStatus(group).untested }}</span>
                </div>
              </div>
              <div class="group-current">
                <span>当前策略</span><strong>{{ group.mode === 'manual' ? group.selected || '未选择' : '自动优选' }}</strong><small>{{ group.members.length }} 个成员 · {{ group.references }} 个引用</small>
              </div>
              <div class="group-actions">
                <select :value="group.mode === 'manual' ? group.selected || '' : ''" :aria-label="`${group.tag} 当前策略`" @change="groupSelectionChange(group, $event)">
                  <option value="">自动优选</option><option v-for="member in group.members" :key="member" :value="member">固定 · {{ member }}</option>
                </select>
                <button :disabled="testing" title="组内测速" @click="testExits(group.members)"><Gauge :size="16" /></button>
                <button v-if="!group.default" title="设为默认出口" @click="setFinal(group.tag)"><House :size="16" /></button>
                <button title="编辑组成员" @click="editGroup(group)"><Pencil :size="16" /></button>
                <button title="查看组内节点" @click="openGroupNodes(group)"><ListTree :size="16" /></button>
              </div>
              <div v-if="isGroupExpanded(group.tag)" class="group-node-grid">
                <button v-for="node in nodesForGroup(group).slice(0, 80)" :key="node.tag" :class="[{ active: group.selected === node.tag }, delayTone(node.tag)]" @click="setGroupSelection(group, node.tag)">
                  <span v-if="nodeNameParts(node.tag).flag" class="node-flag">{{ nodeNameParts(node.tag).flag }}</span>
                  <span class="group-node-name">{{ nodeNameParts(node.tag).name }}</span>
                  <small>{{ node.type }}</small>
                  <em>{{ delays[node.tag]?.ok ? `${delays[node.tag].delay} ms` : delays[node.tag] ? '失败' : '未测' }}</em>
                </button>
                <p v-if="nodesForGroup(group).length > 80" class="muted">仅显示前 80 个节点，请进入详情筛选。</p>
              </div>
            </article>
            <p v-if="!visibleGroups.length" class="empty">没有匹配的策略组</p>
          </div>
        </section>
        <section v-if="nodeWorkspace === 'nodes'" class="node-browser standalone">
          <div class="node-toolbar">
            <div>
              <p class="eyebrow">{{ activeNodeGroup ? 'GROUP MEMBERS' : 'ALL OUTBOUNDS' }}</p>
              <h2>{{ activeNodeGroup?.tag || subscriptions.find(item => item.id === nodeSourceFilter)?.label || '全部节点' }} <span>{{ visibleNodes.length }}</span></h2>
            </div>
            <div class="node-tools">
              <input v-model="nodeSearch" class="search" placeholder="搜索节点、协议、地址或来源" />
              <select v-model="nodeStatusFilter"><option value="all">全部状态</option><option value="available">可用</option><option value="failed">失败</option><option value="untested">未测速</option></select>
              <select v-model="nodeSourceFilter"><option value="all">全部来源</option><option v-for="item in subscriptions" :key="item.id" :value="item.id">{{ item.label }}</option></select>
              <select v-model="nodeSort"><option value="source">配置顺序</option><option value="name">名称排序</option><option value="delay">延迟排序</option></select>
              <button class="view-toggle" :class="{ active: nodeView === 'list' }" @click="nodeView = 'list'">列表</button>
              <button class="view-toggle" :class="{ active: nodeView === 'grid' }" @click="nodeView = 'grid'">卡片</button>
            </div>
          </div>
          <div v-if="activeNodeGroup" class="active-group-bar">
            <label>当前策略<select :value="activeNodeGroup.mode === 'manual' ? activeNodeGroup.selected || '' : ''" @change="groupSelectionChange(activeNodeGroup, $event)"><option value="">自动优选</option><option v-for="member in activeNodeGroup.members" :key="member" :value="member">固定 · {{ member }}</option></select></label>
            <span>{{ activeNodeGroup.default ? '默认出口' : `${activeNodeGroup.references} 个引用` }}</span>
            <button :disabled="testing" title="组内测速" @click="testExits(activeNodeGroup.members)"><Gauge :size="16" /></button>
            <button v-if="!activeNodeGroup.default" title="设为默认出口" @click="setFinal(activeNodeGroup.tag)"><House :size="16" /></button>
            <button title="编辑组成员" @click="editGroup(activeNodeGroup)"><Pencil :size="16" /></button>
          </div>
          <div class="node-collection" :class="nodeView">
            <article v-for="item in visibleNodes" :key="item.tag" class="node-item" :class="{ selected: item.default, active: activeNodeGroup?.selected === item.tag }">
              <div class="node-identity">
                <span v-if="nodeNameParts(item.tag).flag" class="node-flag">{{ nodeNameParts(item.tag).flag }}</span>
                <div><span class="protocol">{{ item.type }}</span><strong>{{ nodeNameParts(item.tag).name }}</strong><small>{{ item.server || '本机直出' }}<template v-if="item.server_port">:{{ item.server_port }}</template></small></div>
              </div>
              <span v-if="item.default" class="badge">默认</span><span v-else-if="activeNodeGroup?.selected === item.tag" class="badge">已固定</span>
              <span class="node-source">{{ item.subscription_label || (item.source === 'system' ? '系统' : '手工') }}</span>
              <span class="node-delay" :class="delayTone(item.tag)">{{ delays[item.tag]?.ok ? `${delays[item.tag].delay} ms` : delays[item.tag] ? '失败' : '未测' }}</span>
              <span class="node-reference">{{ item.references }} 引用</span>
              <div class="row-actions">
                <button :disabled="testing" title="测速" @click="testExits([item.tag])"><Gauge :size="15" /></button>
                <button v-if="activeNodeGroup && activeNodeGroup.selected !== item.tag" title="固定到当前策略组" @click="setGroupSelection(activeNodeGroup, item.tag)"><Pin :size="15" /></button>
                <button v-if="!item.default" title="设为默认出口" @click="setFinal(item.tag)"><House :size="15" /></button>
                <button v-if="item.deletable" class="text-danger" title="删除节点" @click="removeExit(item)"><Trash2 :size="15" /></button>
              </div>
            </article>
            <p v-if="!visibleNodes.length" class="empty">没有匹配的节点</p>
          </div>
        </section>
      </template>

      <template v-if="page === 'rules'">
        <section class="workspace-switcher rules-switcher">
          <div class="segmented-control">
            <button :class="{ active: ruleWorkspace === 'rules' }" @click="ruleWorkspace = 'rules'">规则 <span>{{ rules.length }}</span></button>
            <button :class="{ active: ruleWorkspace === 'providers' }" @click="ruleWorkspace = 'providers'">规则集 <span>{{ rulesets.length }}</span></button>
          </div>
          <div class="command-bar">
            <button class="secondary compact" @click="showRouteTester = !showRouteTester">路由测试</button>
            <button v-if="ruleWorkspace === 'rules'" class="primary compact" @click="showRuleComposer = !showRuleComposer"><Plus :size="15" />新增规则</button>
            <button v-else class="primary compact" @click="showRulesetComposer = !showRulesetComposer"><Plus :size="15" />添加规则集</button>
          </div>
        </section>
        <section v-if="showRouteTester" class="panel route-tester command-panel">
          <div><p class="eyebrow">ROUTE TEST</p><h2>查询域名最终出口</h2></div>
          <div class="route-test-form"><input v-model="routeDomain" placeholder="输入域名" @keyup.enter="testRoute" /><button class="secondary" @click="testRoute">测试</button></div>
          <div v-if="routeResult" class="route-result"><span>{{ routeResult.domain }}</span><strong>{{ routeResult.target }}</strong><small>{{ routeResult.kind }} · {{ routeResult.match }}</small></div>
        </section>
        <section v-if="ruleWorkspace === 'rules' && showRuleComposer" class="panel command-panel">
          <div class="form-grid">
            <input v-model="ruleDomain" placeholder="输入域名，例如 netflix.com" @keyup.enter="saveRule" />
            <select v-model="ruleTarget"><option value="direct">direct · 直连</option><option v-for="item in exits" :key="item.tag" :value="item.tag">{{ item.tag }} · {{ item.type }}</option></select>
            <button class="primary" @click="saveRule">保存规则</button>
          </div>
        </section>
        <template v-if="ruleWorkspace === 'rules'">
          <section class="rule-facets">
            <div class="facet-row">
              <button :class="{ active: ruleKindFilter === 'all' }" @click="ruleKindFilter = 'all'">全部 {{ rules.length }}</button>
              <button :class="{ active: ruleKindFilter === 'domain' }" @click="ruleKindFilter = 'domain'">域名 {{ ruleKindCounts.domain }}</button>
              <button :class="{ active: ruleKindFilter === 'direct' }" @click="ruleKindFilter = 'direct'">直连 {{ ruleKindCounts.direct }}</button>
              <button :class="{ active: ruleKindFilter === 'ruleset' }" @click="ruleKindFilter = 'ruleset'">规则集 {{ ruleKindCounts.ruleset }}</button>
            </div>
            <div class="facet-row policy-facets">
              <button :class="{ active: ruleTargetFilter === 'all' }" @click="ruleTargetFilter = 'all'">全部目标</button>
              <button v-for="policy in policyTargets" :key="policy.target" :class="{ active: ruleTargetFilter === policy.target }" @click="ruleTargetFilter = policy.target">{{ policy.target }} <span>{{ policy.count }}</span></button>
            </div>
          </section>
          <section class="panel policy-table-panel">
            <div class="section-title rules-heading">
              <div><p class="eyebrow">POLICIES</p><h2>规则清单 <span class="muted">{{ filteredRules.length }}</span></h2></div>
              <div class="rule-tools">
                <select v-model="ruleSort"><option value="source">配置顺序</option><option value="name">名称排序</option><option value="target">目标排序</option></select>
                <input v-model="search" class="search" placeholder="搜索规则或目标" />
              </div>
            </div>
            <div class="policy-table-head"><span>规则</span><span>目标策略</span><span>规模</span><span>操作</span></div>
            <div class="rule-list">
              <div v-for="item in filteredRules" :key="`${item.kind}-${item.value}-${item.target}`" class="rule-row">
                <div><span class="kind">#{{ item.order + 1 }} · {{ item.kind === 'ruleset' ? '规则集' : item.kind === 'direct' ? '直连' : '域名' }}</span><strong>{{ item.label }}</strong><small v-if="item.label !== item.value">{{ item.value }}</small></div>
                <select v-if="item.kind !== 'ruleset'" class="quick-target" :value="item.target" @change="ruleTargetChange(item, $event)"><option value="direct">direct</option><option v-for="exit in exits" :key="exit.tag" :value="exit.tag">{{ exit.tag }}</option></select>
                <div v-else class="rule-target"><span>→</span><strong>{{ item.target }}</strong></div>
                <span class="muted">{{ item.count ? `${item.count} 条` : '单条' }}</span>
                <button v-if="item.kind !== 'ruleset'" class="text-danger" @click="removeRule(item)">删除</button>
                <button v-else @click="ruleWorkspace = 'providers'">查看规则集</button>
              </div>
              <p v-if="!filteredRules.length" class="empty">没有匹配的分流规则</p>
            </div>
          </section>
        </template>
        <template v-else>
          <section v-if="showRulesetComposer" class="panel command-panel">
            <div class="ruleset-form">
              <input v-model="rulesetUrl" placeholder="https://example.com/media.list 或 rules.srs" />
              <input v-model="rulesetLabel" placeholder="显示名称（可选）" />
              <select v-model="rulesetTarget"><option v-for="item in exits" :key="item.tag" :value="item.tag">{{ item.tag }}</option></select>
              <button class="primary" @click="saveRuleset">下载并应用</button>
            </div>
          </section>
          <section class="rule-provider-grid">
            <article v-for="item in rulesets" :key="item.tag" class="rule-provider-card" :class="{ degraded: !item.available || item.last_error }">
              <div class="rule-provider-head"><div><span class="kind">{{ item.format }}</span><h3>{{ item.label }}</h3><small>{{ item.url }}</small></div><span :class="item.available && !item.last_error ? 'good' : 'bad'">{{ item.available && !item.last_error ? '可用' : '异常' }}</span></div>
              <div class="rule-provider-meta"><strong>{{ item.count === null ? '二进制' : item.count }}</strong><span>{{ item.count === null ? '规则格式' : '规则条目' }}</span><small>{{ formatTime(item.updated_at) }}</small></div>
              <p v-if="item.last_error" class="bad">{{ item.last_error }}</p>
              <label>目标策略<select :value="item.target" @change="rulesetTargetChange(item, $event)"><option v-for="exit in exits" :key="exit.tag" :value="exit.tag">{{ exit.tag }}</option></select></label>
              <div class="provider-actions"><button @click="updateRuleset(item)">改名</button><button @click="refreshRuleset(item)">刷新</button><button class="text-danger" @click="removeRuleset(item)">删除</button></div>
            </article>
            <p v-if="!rulesets.length" class="empty">尚未添加规则集</p>
          </section>
        </template>
      </template>

      <template v-if="page === 'resources'">
        <section class="panel preset-panel">
          <div class="section-title"><div><p class="eyebrow">SUBSCRIPTION OVERRIDES</p><h2>节点订阅覆写</h2></div></div>
          <p class="preset-intro">覆写用于整理节点订阅，不是远程脚本。先选择订阅，再套用模板；系统会下载并展示差异，确认后才写入配置。</p>
          <label class="preset-target">应用到订阅
            <select v-model="presetSubscriptionId" :disabled="!subscriptions.length">
              <option v-if="!subscriptions.length" value="">请先在节点页添加订阅</option>
              <option v-for="item in subscriptions" :key="item.id" :value="item.id">{{ item.label }} · {{ item.count }} 个节点</option>
            </select>
          </label>
          <div class="preset-grid">
            <article v-for="preset in overridePresets" :key="preset.id" class="preset-card">
              <div><strong>{{ preset.name }}</strong><p>{{ preset.description }}</p></div>
              <button class="secondary" :disabled="!presetSubscriptionId" @click="applyOverridePreset(preset)">套用并预览</button>
            </article>
          </div>
        </section>
        <section class="panel preset-panel">
          <div class="section-title"><div><p class="eyebrow">RULESET GALLERY</p><h2>常用 GitHub 规则集</h2></div></div>
          <p class="preset-intro">来源为 <strong>blackmatrix7/ios_rule_script</strong> 和 <strong>DustinWin/ruleset_geodata</strong>。安装前请选择流量出口；下载后仍会经过格式解析、sing-box 校验和失败回滚。</p>
          <label class="preset-target">规则集出口
            <select v-model="presetRulesetTarget">
              <option v-for="item in exits" :key="item.tag" :value="item.tag">{{ item.tag }} · {{ item.type }}</option>
            </select>
          </label>
          <div class="preset-grid ruleset-presets">
            <article v-for="preset in rulesetPresets" :key="preset.name" class="preset-card">
              <div><strong>{{ preset.name }}</strong><p>{{ preset.description }}</p></div>
              <button class="secondary" :disabled="resourceBusy === `preset-${preset.name}`" @click="installRulesetPreset(preset)">下载并应用</button>
            </article>
          </div>
        </section>
        <section class="resource-grid">
          <article class="resource-card">
            <div class="resource-head"><Database :size="21" /><div><h2>节点订阅</h2><span>{{ subscriptions.length }} 个来源 · {{ subscriptions.reduce((sum, item) => sum + item.count, 0) }} 个节点</span></div></div>
            <p>按来源刷新并重新应用过滤、重命名、排序和属性覆写；失败保留旧节点。</p>
            <button class="secondary" :disabled="resourceBusy === 'subscriptions'" @click="refreshResource('subscriptions')"><RefreshCw :size="16" />全部刷新</button>
          </article>
          <article class="resource-card">
            <div class="resource-head"><Route :size="21" /><div><h2>远程规则集</h2><span>{{ rulesets.length }} 个资源</span></div></div>
            <p>下载候选、校验 sing-box 配置，成功后原子替换；失败自动回滚。</p>
            <button class="secondary" :disabled="resourceBusy === 'rulesets'" @click="refreshResource('rulesets')"><RefreshCw :size="16" />全部刷新</button>
          </article>
          <article class="resource-card">
            <div class="resource-head"><Network :size="21" /><div><h2>Geosite 数据</h2><span>{{ resources?.geosite.available ? '资源完整' : '资源缺失' }} · {{ formatTime(resources?.geosite.updated_at) }}</span></div></div>
            <p>更新 mosdns 使用的国内、国际和 Apple 域名数据，成功后重载 DNS。</p>
            <button class="secondary" :disabled="resourceBusy === 'geosite'" @click="refreshResource('geosite')"><RefreshCw :size="16" />在线更新</button>
          </article>
          <article class="resource-card" :class="{ attention: resources?.project.update_available }">
            <div class="resource-head"><Server :size="21" /><div><h2>PrivDNS Gateway</h2><span>{{ resources?.project.current || '未知版本' }}<template v-if="resources?.project.latest"> · 最新 {{ resources.project.latest }}</template></span></div></div>
            <p>从项目发布仓库检查更新，后台执行现有 pdg update 快照、校验和回滚流程。</p>
            <div class="row-actions start"><button @click="checkProjectUpdate"><Search :size="16" />检查</button><button v-if="resources?.project.update_available" class="primary compact" @click="startProjectUpdate">立即更新</button></div>
          </article>
        </section>
        <section class="panel">
          <div class="section-title"><div><p class="eyebrow">RESOURCE STATUS</p><h2>最近状态</h2></div><button class="secondary" @click="loadResources"><RefreshCw :size="16" />刷新状态</button></div>
          <div class="resource-list">
            <div v-for="item in subscriptions" :key="item.id"><span class="kind">订阅</span><strong>{{ item.label }}</strong><small>{{ formatTime(item.updated_at) }}</small><em :class="item.last_error ? 'bad' : 'good'">{{ item.last_error || '正常' }}</em></div>
            <div v-for="item in rulesets" :key="item.tag"><span class="kind">规则集</span><strong>{{ item.label }}</strong><small>{{ formatTime(item.updated_at) }}</small><em :class="item.last_error ? 'bad' : 'good'">{{ item.last_error || (item.available ? '正常' : '文件缺失') }}</em></div>
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
        <component :is="item.icon" :size="19" />{{ item.label }}
      </button>
    </nav>
  </div>
</template>
