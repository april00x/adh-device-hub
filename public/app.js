/* 设备身份中枢 - 前端逻辑（Vue 3 Options API，无需构建） */
const { createApp } = Vue;

const RANGES = [
  { k: '1h', label: '1 小时' },
  { k: '24h', label: '24 小时' },
  { k: '7d', label: '7 天' },
  { k: '30d', label: '30 天' }
];

const app = createApp({
  data() {
    return {
      booting: true,
      setupDone: true,
      me: null,
      authForm: { username: 'admin', password: '' },
      authError: '',
      busy: false,
      busyCollect: false,

      view: 'dashboard',
      ranges: RANGES,
      range: '24h',

      devices: [],
      hints: [],
      deviceQuery: '',
      deviceFilter: 'all',
      deviceFilters: [
        { k: 'all', label: '全部' },
        { k: 'active', label: '24h 活跃' },
        { k: 'named', label: '已命名' },
        { k: 'unnamed', label: '未命名' },
        { k: 'random', label: '随机MAC' }
      ],
      // 台账：分类/标签筛选、多选批量、内联改名
      selected: [],
      deviceCategory: '',
      deviceTag: '',
      editingNameId: null,
      editingNameValue: '',
      bulkCategory: '',
      bulkTag: '',
      // 运行状态 / 主域名聚合
      status: null,
      rootDomains: false,
      // 日志页：未归属 IP 汇总与指派
      unmappedIps: [],
      assignModal: false,
      assignIpAddr: '',
      assignDeviceId: '',
      assignMode: 'logs',         // logs = 查询日志，sink = 拦截流量分析
      deviceTops: { allowed: [], blocked: [] },
      // AdGuard 客户端管理
      agh: { clients: [], auto_clients: [], write_allowed: false, auto_sync: false },
      aghStale: [],
      aghModal: false,
      aghForm: { name: '', deviceId: '' },
      aghPlan: null,
      aghBusy: false,
      aghSel: [],                 // 勾选的客户端名
      aghBatch: null,             // 批量/全量预览结果
      aghBatchModal: false,
      aghBatchScope: [],          // 批量范围（空 = 全量）
      aghIncludeUnknown: false,   // 是否一并清理"本系统认不出"的地址（默认否）
      // 拦截流量分析：AdGuard 拦截后指向本机的连接在此留痕
      sink: {
        status: null,
        ov: { events: 0, hits: 0, hosts: 0, devices: 0, mapped: 0, decrypted: 0, sni_only: 0, trend: [], protos: [] },
        devices: [], hosts: [], uas: [], fps: [], rows: [], total: 0, page: 1, size: 50, unmapped: []
      },
      sinkFilter: { deviceId: '', proto: '', host: '', ua: '', q: '', ja4: '', lport: '', outcome: '', decrypted: '', bodyKind: '', body: '', range: '24h' },
      sinkAggMode: 'ua',          // 第三张榜：按 UA 还是按 JA4 指纹
      sinkExpandId: null,         // 展开明细的行
      sinkExpandAll: false,       // 一键展开全部行
      sinkShowUnmapped: false,
      sinkBusy: false,
      categories: [
        { k: 'phone', label: '手机' }, { k: 'laptop', label: '电脑' },
        { k: 'tv', label: '电视/盒子' }, { k: 'tablet', label: '平板' },
        { k: 'iot', label: '智能家居' }, { k: 'nas', label: 'NAS/服务器' },
        { k: 'router', label: '网络设备' }, { k: 'other', label: '其他' }
      ],

      detail: null,
      newIp: '',

      ov: { total: 0, blocked: 0, blocked_rate: 0, devices: 0, named: 0, matched: 0, local: 0, unmapped: 0, active24: 0, trend: [], topDevices: [], topBlocked: [] },
      jobs: [],

      logFilter: { deviceId: '', blocked: '', domain: '', clientIp: '', range: '24h' },
      logs: { rows: [], total: 0, page: 1, size: 50 },

      settings: {},
      settingsSaved: '',          // 服务端当前设置快照，用于提示"有未保存的改动"
      dbInfo: null,
      // 运行环境（本机系统/硬件/温度），字段初始给空壳，模板可直接取值
      sys: { host: {}, cpu: { load: [], temps: [] }, memory: {}, disk: null, net: [], runtime: {} },
      sysLoaded: false,
      sysBusy: false,
      connections: [],
      ouiStats: {},
      pwd: { old: '', next: '' },

      deviceModal: false,
      editing: {},
      mergeModal: false,
      mergeSource: {},
      mergeTargetId: '',
      connModal: false,
      connForm: {},
      testModal: false,
      testResult: { ok: false, text: '' },

      toasts: []
    };
  },

  computed: {
    filteredDevices() {
      const q = this.deviceQuery.toLowerCase();
      let list = this.devices;
      if (this.deviceFilter === 'active') list = list.filter((d) => d.last_seen && Date.now() - Date.parse(d.last_seen) < 86400000);
      else if (this.deviceFilter === 'named') list = list.filter((d) => !!d.name);
      else if (this.deviceFilter === 'unnamed') list = list.filter((d) => !d.name);
      else if (this.deviceFilter === 'random') list = list.filter((d) => d.random_mac);
      if (this.deviceCategory === '__none__') list = list.filter((d) => !d.category);
      else if (this.deviceCategory) list = list.filter((d) => d.category === this.deviceCategory);
      if (this.deviceTag) list = list.filter((d) => (d.tags || []).includes(this.deviceTag));
      if (q) {
        list = list.filter((d) =>
          (d.display_name || '').toLowerCase().includes(q) ||
          (d.suggested_name || '').toLowerCase().includes(q) ||
          (d.vendor || '').toLowerCase().includes(q) ||
          (d.mac || '').toLowerCase().includes(q) ||
          (d.current_ips || []).some((ip) => ip.toLowerCase().includes(q)));
      }
      return list;
    },
    rangeLabel() {
      const r = RANGES.find((x) => x.k === this.range);
      return r ? '近 ' + r.label : '';
    },
    /** 连接/任务异常提示（首页顶部横幅） */
    connWarning() {
      const s = this.status;
      if (!s) return '';
      if (!s.ssh_configured) return '未配置可用的 SSH 连接，设备 IP 归并将不可用（设置 → 连接配置）';
      if (!s.adguard_configured) return '未配置可用的 AdGuard 连接，无法摄取查询日志（设置 → 连接配置）';
      const last = (s.last_runs || [])[0];
      if (last && last.status === 'failed') return `最近任务失败（${last.job}）：${last.message || '未知原因'}`;
      return '';
    },
    allSelected() {
      const list = this.filteredDevices;
      return list.length > 0 && list.every((d) => this.selected.includes(d.id));
    },
    categoryOptions() {
      return [...new Set(this.devices.map((d) => d.category).filter(Boolean))].sort();
    },
    anomalies() { return this.ov.anomalies || []; },
    /** 拦截 Top 设备卡片：条形图以榜首为满格，便于比较差距 */
    topBlockedDevices() { return this.ov.topBlockedDevices || []; },
    topBlockedMax() {
      let max = 0;
      for (const d of this.topBlockedDevices) max = Math.max(max, d.blocked || 0);
      return max;
    },
    isAghWriteOn() { return String((this.settings || {}).allow_agh_write || '0') === '1'; },
    isAghAutoSyncOn() { return String((this.settings || {}).agh_auto_sync || '0') === '1'; },
    isSinkOn() { return String((this.settings || {}).sink_enabled || '0') === '1'; },
    isSinkHeadersOn() { return String((this.settings || {}).sink_capture_headers || '0') === '1'; },
    isSinkBodyOn() { return String((this.settings || {}).sink_capture_body || '0') === '1'; },
    /** 拦截流量分析卡片里是否有未保存的改动（这些开关同样要点「保存设置」才生效） */
    sinkDirty() {
      if (!this.settingsSaved) return false;
      let saved = {};
      try { saved = JSON.parse(this.settingsSaved); } catch (e) { return false; }
      return Object.keys(this.settings || {})
        .filter((k) => k.startsWith('sink_'))
        .some((k) => String(this.settings[k]) !== String(saved[k]));
    },
    /** 自动同步是「允许写回」的子开关：总开关关着时，这里要显示成"已暂停"，否则会让人误以为在生效 */
    aghAutoSyncLabel() {
      if (!this.isAghWriteOn) return this.isAghAutoSyncOn ? '已配置，但总开关关闭（不会写）' : '已暂停（总开关未开）';
      return this.isAghAutoSyncOn ? '已开启' : '已关闭（默认）';
    },
    aghAutoSyncBadge() {
      if (!this.isAghWriteOn) return this.isAghAutoSyncOn ? 'warn' : '';
      return this.isAghAutoSyncOn ? 'warn' : 'ok';
    },
    aghAllSelected() {
      const list = (this.agh.clients || []).filter((c) => c.managed);
      return list.length > 0 && list.every((c) => this.aghSel.includes(c.name));
    },
    aghManagedCount() { return (this.agh.clients || []).filter((c) => c.managed).length; },
    aghPendingCount() { return (this.agh.clients || []).filter((c) => c.state === 'pending').length; },
    /** CPU 频率文案（sysfs 只给 kHz，后端已换成 MHz） */
    cpuFreqText() {
      const c = this.sys.cpu || {};
      if (!c.cur_mhz) return '不可用';
      return c.max_mhz ? `${c.cur_mhz} / ${c.max_mhz} MHz` : `${c.cur_mhz} MHz`;
    },
    cpuLoadText() {
      return (this.sys.cpu.load || []).map((n) => Number(n).toFixed(2)).join(' / ');
    },
    /** 温度过高时标红：服务器/小主机长期高于 70°C 就该查散热了 */
    cpuTempClass() {
      const t = (this.sys.cpu || {}).temp;
      if (t === null || t === undefined) return 'muted';
      if (t >= 75) return 't-danger';
      if (t >= 65) return 't-warn';
      return 't-ok';
    },
    tagOptions() {
      return [...new Set(this.devices.flatMap((d) => d.tags || []))].sort();
    },
    /** 日志页导出 CSV 的地址（带当前筛选） */
    logsExportUrl() {
      const qs = this.buildLogQuery();
      return '/api/export/logs.csv?' + qs;
    },
    /* ---------- 拦截流量分析 ---------- */
    sinkStatus() { return this.sink.status || {}; },
    /** TLS 连接里成功解出明文的比例（明文 HTTP 不需要解密，单独算在 with_content 里，不进这个分母） */
    sinkDecryptRate() {
      const ov = this.sink.ov || {};
      const total = Number(ov.decrypted || 0) + Number(ov.sni_only || 0);
      if (!total) return '—';
      return (Number(ov.decrypted) / total * 100).toFixed(1);
    },
    sinkResponseLabel() {
      const map = { empty: '204 空响应', close: '直接关闭连接', page: '返回提示页' };
      return map[this.sinkStatus.response] || '—';
    },
    /** 流量详情表导出 CSV 的地址（带当前筛选） */
    sinkExportUrl() {
      return '/api/sink/export.csv?' + this.buildSinkQuery();
    }
  },

  mounted() {
    this.boot();
    this._timer = setInterval(() => {
      if (!this.me) return;
      if (this.view === 'dashboard') this.loadOverview();
      if (this.view === 'devices') this.loadDevices();
      if (this.view === 'sink') this.loadSink();          // 拦截流量分析的状态与写入缓冲都是实时值，停在本页时自动刷新
      if (this.view === 'settings') this.loadSysinfo();   // 温度/负载/内存是实时值，停在本页时自动刷新
    }, 30000);
    this._onResize = () => {
      if (this._chart) this._chart.resize();
      if (this._sinkChart) this._sinkChart.resize();
    };
    window.addEventListener('resize', this._onResize);
  },
  beforeUnmount() {
    clearInterval(this._timer);
    window.removeEventListener('resize', this._onResize);
    if (this._chart) { this._chart.dispose(); this._chart = null; }
    if (this._sinkChart) { this._sinkChart.dispose(); this._sinkChart = null; }
  },

  methods: {
    /* ---------- 基础 ---------- */
    async api(path, opts = {}) {
      const res = await fetch('/api' + path, {
        method: opts.method || 'GET',
        headers: { 'Content-Type': 'application/json' },
        credentials: 'same-origin',
        body: opts.body === undefined ? undefined : JSON.stringify(opts.body)
      });
      // 401 表示会话过期，此时清掉登录态并回登录页；但 /login 自身返回 401 表示"用户名或密码错误"，
      // 那时要保留服务端的原始提示，不能被"登录已过期"顶掉
      if (res.status === 401 && path !== '/login') { this.me = null; throw new Error('登录已过期，请重新登录'); }
      const text = await res.text();
      let data = null;
      try { data = text ? JSON.parse(text) : null; } catch (e) { data = { raw: text }; }
      if (!res.ok) throw new Error((data && data.error) || ('请求失败 HTTP ' + res.status));
      return data;
    },
    toast(text, type = 'info') {
      const id = Math.random().toString(36).slice(2);
      this.toasts.push({ id, text, type });
      setTimeout(() => { this.toasts = this.toasts.filter((t) => t.id !== id); }, type === 'err' ? 6000 : 3200);
    },
    fmtNum(n) { return Number(n || 0).toLocaleString('zh-CN'); },
    blockedShare(d) {
      const all = Number(this.ov.blocked || 0);
      if (!all) return '0.0';
      return (d.blocked / all * 100).toFixed(1);
    },
    /** 条形宽度：以榜首为满格（最小 2% 保证可见） */
    blockedBar(d) {
      if (!this.topBlockedMax) return '0%';
      return Math.max(2, Math.round(d.blocked / this.topBlockedMax * 100)) + '%';
    },
    fmtBytes(n) {
      const v = Number(n);
      if (!Number.isFinite(v) || v <= 0) return '0 B';
      const units = ['B', 'KB', 'MB', 'GB', 'TB'];
      let x = v;
      let i = 0;
      while (x >= 1024 && i < units.length - 1) { x /= 1024; i += 1; }
      return `${i === 0 || x >= 100 ? Math.round(x) : x.toFixed(1)} ${units[i]}`;
    },
    fmtDur(sec) {
      const s = Math.max(0, Math.floor(Number(sec) || 0));
      const d = Math.floor(s / 86400);
      const h = Math.floor((s % 86400) / 3600);
      const m = Math.floor((s % 3600) / 60);
      if (d) return `${d} 天 ${h} 小时`;
      if (h) return `${h} 小时 ${m} 分`;
      if (m) return `${m} 分 ${s % 60} 秒`;
      return `${s} 秒`;
    },
    /** 台账数据的"距今多久"（后端 data_age_sec） */
    fmtAge(sec) {
      if (sec === null || sec === undefined) return '未知';
      const s = Math.max(0, Math.floor(Number(sec) || 0));
      if (s < 90) return `${s} 秒前`;
      if (s < 3600) return `${Math.round(s / 60)} 分钟前`;
      if (s < 86400) return `${(s / 3600).toFixed(1)} 小时前`;
      return `${(s / 86400).toFixed(1)} 天前`;
    },
    fmtTime(t) {
      if (!t) return '—';
      const d = typeof t === 'number' ? new Date(t) : new Date(t);
      if (Number.isNaN(d.getTime())) return '—';
      const p = (x) => String(x).padStart(2, '0');
      return `${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())} ${p(d.getHours())}:${p(d.getMinutes())}:${p(d.getSeconds())}`;
    },
    /** 列表里用的短时间：当天只显示 HH:MM:SS，跨天显示 MM-DD HH:MM（完整时间在悬停提示里） */
    fmtTimeShort(t) {
      if (!t) return '—';
      const d = new Date(t);
      if (Number.isNaN(d.getTime())) return '—';
      const p = (x) => String(x).padStart(2, '0');
      const hms = `${p(d.getHours())}:${p(d.getMinutes())}:${p(d.getSeconds())}`;
      return d.toDateString() === new Date().toDateString()
        ? hms
        : `${p(d.getMonth() + 1)}-${p(d.getDate())} ${p(d.getHours())}:${p(d.getMinutes())}`;
    },
    relTime(t) {
      if (!t) return '—';
      const ms = Date.now() - Date.parse(t);
      if (Number.isNaN(ms)) return '—';
      if (ms < 60000) return '刚刚';
      if (ms < 3600000) return Math.floor(ms / 60000) + ' 分钟前';
      if (ms < 86400000) return Math.floor(ms / 3600000) + ' 小时前';
      return Math.floor(ms / 86400000) + ' 天前';
    },
    /** 同步窗口（秒）→ "48 小时" / "3 天"；用于展示"多久没出现算过期" */
    fmtWindow(sec) {
      const h = (Number(sec) || 86400) / 3600;
      if (h >= 24 && h % 24 === 0) return `${h / 24} 天`;
      return `${Math.round(h * 10) / 10} 小时`;
    },
    categoryLabel(k) { const c = this.categories.find((x) => x.k === k); return c ? c.label : '未分类'; },

    /* ---------- 认证 ---------- */
    async boot() {
      try {
        const s = await this.api('/setup/status');
        this.setupDone = s.setup_done;
        if (this.setupDone) {
          try { const m = await this.api('/me'); this.me = m.user; await this.loadAll(); } catch (e) { this.me = null; }
        }
      } catch (e) { this.authError = e.message; }
      this.booting = false;
    },
    async submitAuth() {
      this.authError = '';
      if (!this.authForm.username || !this.authForm.password) { this.authError = '请输入用户名和密码'; return; }
      this.busy = true;
      try {
        if (!this.setupDone) await this.api('/setup', { method: 'POST', body: this.authForm });
        else await this.api('/login', { method: 'POST', body: this.authForm });
        const m = await this.api('/me');
        this.me = m.user;
        this.setupDone = true;
        this.authForm.password = '';
        await this.loadAll();
      } catch (e) { this.authError = e.message; }
      this.busy = false;
    },
    async logout() {
      try { await this.api('/logout', { method: 'POST' }); } catch (e) { /* ignore */ }
      this.me = null;
      this.authForm.password = '';
    },
    async changePwd() {
      try {
        await this.api('/password', { method: 'POST', body: { old_password: this.pwd.old, new_password: this.pwd.next } });
        this.pwd = { old: '', next: '' };
        this.toast('密码已修改', 'ok');
      } catch (e) { this.toast(e.message, 'err'); }
    },

    /* ---------- 数据加载 ---------- */
    async loadAll() {
      await Promise.all([
        this.loadDevices(), this.loadOverview(), this.loadSettings(),
        this.loadConnections(), this.loadJobs(), this.loadOui(), this.loadStatus(), this.loadAgh(),
        this.loadSinkStatus()
      ]);
    },
    async loadStatus() {
      try { this.status = await this.api('/status'); } catch (e) { /* 静默 */ }
    },
    setRootDomains(v) {
      this.rootDomains = v;
      this.loadOverview();
      if (this.view === 'device' && this.detail) this.loadDeviceTops(this.detail.id);
    },
    async loadDeviceTops(deviceId) {
      try {
        const [allowed, blocked] = await Promise.all([
          this.api('/stats/top?deviceId=' + deviceId + '&limit=15&root=' + this.rootDomains),
          this.api('/stats/top?deviceId=' + deviceId + '&blocked=true&limit=15&root=' + this.rootDomains)
        ]);
        this.deviceTops = { allowed: allowed.rows, blocked: blocked.rows };
      } catch (e) { this.deviceTops = { allowed: [], blocked: [] }; }
    },
    async loadDevices() {
      try {
        const d = await this.api('/devices?filter=all');
        this.devices = d.devices;
        this.hints = d.hints || [];
      } catch (e) { this.toast(e.message, 'err'); }
    },
    async loadOverview() {
      try {
        this.ov = await this.api('/overview?range=' + this.range + '&root=' + this.rootDomains);
        this.$nextTick(this.renderTrend);
      } catch (e) { /* 静默 */ }
    },
    async loadJobs() {
      try { const d = await this.api('/jobs'); this.jobs = d.jobs.slice(0, 12); } catch (e) { /* ignore */ }
    },
    async loadSettings() {
      try {
        this.settings = (await this.api('/settings')).settings;
        // 记下"服务端当前的值"，用于提示卡片里是否有未保存的改动
        this.settingsSaved = JSON.stringify(this.settings);
      } catch (e) { /* ignore */ }
    },
    async loadConnections() {
      try { this.connections = (await this.api('/connections')).connections; } catch (e) { /* ignore */ }
    },
    async loadOui() {
      try { this.ouiStats = await this.api('/oui/stats'); } catch (e) { /* ignore */ }
    },
    renderTrend() {
      const el = this.$refs.trend;
      if (!el || !window.echarts) return;
      if (!this._chart || this._chart.getDom() !== el) {
        if (this._chart) this._chart.dispose();
        this._chart = echarts.init(el, 'dark', { backgroundColor: 'transparent' });
      }
      const data = this.ov.trend || [];
      const fmt = (t) => {
        const d = new Date(t); const p = (x) => String(x).padStart(2, '0');
        return this.range === '1h' || this.range === '24h'
          ? `${p(d.getHours())}:${p(d.getMinutes())}`
          : `${p(d.getMonth() + 1)}-${p(d.getDate())}`;
      };
      this._chart.setOption({
        grid: { left: 48, right: 20, top: 30, bottom: 28 },
        tooltip: { trigger: 'axis' },
        legend: { data: ['查询', '拦截'], textStyle: { color: '#a3abb8' }, right: 0, top: 0 },
        xAxis: { type: 'category', data: data.map((d) => fmt(d.t)), axisLine: { lineStyle: { color: '#2a313a' } }, axisLabel: { color: '#7a838f' } },
        yAxis: { type: 'value', splitLine: { lineStyle: { color: '#222831' } }, axisLabel: { color: '#7a838f' } },
        series: [
          { name: '查询', type: 'line', smooth: true, showSymbol: false, data: data.map((d) => d.total), lineStyle: { width: 2, color: '#6b8fc7' }, areaStyle: { color: 'rgba(107,143,199,.14)' } },
          { name: '拦截', type: 'line', smooth: true, showSymbol: false, data: data.map((d) => d.blocked), lineStyle: { width: 2, color: '#e0666f' }, areaStyle: { color: 'rgba(224,102,111,.12)' } }
        ]
      }, true);
    },
    setRange(k) { this.range = k; this.loadOverview(); },

    /* ---------- 操作 ---------- */
    go(v) {
      this.view = v;
      if (v === 'dashboard') { this.loadOverview(); this.loadStatus(); }
      if (v === 'devices') { this.loadDevices(); this.clearSelection(); }
      if (v === 'logs') this.loadLogs(1);
      if (v === 'agh') this.loadAgh();
      if (v === 'sink') this.loadSink();
      if (v === 'settings') { this.loadConnections(); this.loadSettings(); this.loadOui(); this.loadDbInfo(); this.loadSysinfo(); }
    },
    async loadDbInfo() {
      try { this.dbInfo = await this.api('/db/info'); } catch (e) { this.dbInfo = null; }
    },
    /** 运行环境：本机系统 / 硬件 / 温度（只读） */
    async loadSysinfo() {
      this.sysBusy = true;
      try {
        this.sys = await this.api('/sysinfo');
        this.sysLoaded = true;
      } catch (e) { this.toast(e.message, 'err'); }
      this.sysBusy = false;
    },

    /* ---------- 拦截流量分析 ---------- */
    /** 把当前筛选折成查询串：列表与导出 CSV 共用，保证导出的就是看到的 */
    buildSinkQuery(page) {
      const f = this.sinkFilter;
      const q = new URLSearchParams();
      if (f.deviceId) q.set('deviceId', f.deviceId);
      if (f.proto) q.set('proto', f.proto);
      if (f.host) q.set('host', f.host);
      if (f.ua) q.set('ua', f.ua);
      if (f.q) q.set('q', f.q);
      if (f.ja4) q.set('ja4', f.ja4);
      if (f.outcome) q.set('outcome', f.outcome);
      if (f.decrypted !== '') q.set('decrypted', f.decrypted);
      if (f.bodyKind) q.set('bodyKind', f.bodyKind);
      if (f.body) q.set('body', f.body);
      q.set('range', f.range || '24h');
      if (page) { q.set('page', String(page)); q.set('size', String(this.sink.size)); }
      return q.toString();
    },
    /** 只刷新状态（首页轮询用）：状态卡与导航角标要保持最新 */
    async loadSinkStatus() {
      try { this.sink.status = await this.api('/sink/status'); } catch (e) { /* 静默 */ }
    },
    async loadSink() {
      this.sinkBusy = true;
      const range = this.sinkFilter.range || '24h';
      // 主机/UA 聚合只在"按具体设备"筛选时收窄，本机/未归属这类伪设备不传，否则会查出空
      const devForAgg = this.sinkFilter.deviceId && !['local', '__none__'].includes(this.sinkFilter.deviceId)
        ? '&deviceId=' + this.sinkFilter.deviceId : '';
      const protoForAgg = this.sinkFilter.proto ? '&proto=' + this.sinkFilter.proto : '';
      // 上限 30：主机/UA 多的时候不要一次拉几百行，界面上是滚动区
      const aggQ = '?range=' + range + devForAgg + protoForAgg + '&limit=30';
      try {
        const [status, ov, devs, hosts, uas, fps, evts, unmapped] = await Promise.all([
          this.api('/sink/status'),
          this.api('/sink/overview?range=' + range),
          this.api('/sink/stats/devices?range=' + range),
          this.api('/sink/stats/hosts' + aggQ),
          this.api('/sink/stats/uas' + aggQ),
          this.api('/sink/stats/fp' + aggQ),
          this.api('/sink/events?' + this.buildSinkQuery(this.sink.page)),
          this.api('/sink/unmapped-ips?range=' + range)
        ]);
        this.sink.status = status;
        this.sink.ov = ov;
        this.sink.devices = devs.rows || [];
        this.sink.hosts = hosts.rows || [];
        this.sink.uas = uas.rows || [];
        this.sink.fps = fps.rows || [];
        this.sink.rows = evts.rows || [];
        this.sink.total = evts.total || 0;
        this.sink.page = evts.page || 1;
        this.sink.size = evts.size || 50;
        this.sink.unmapped = unmapped.rows || [];
        this.$nextTick(() => this.renderSinkTrend());
      } catch (e) { this.toast(e.message, 'err'); }
      this.sinkBusy = false;
    },
    async loadSinkEvents(page) {
      const p = Math.max(1, Number(page) || 1);
      try {
        const r = await this.api('/sink/events?' + this.buildSinkQuery(p));
        this.sink.rows = r.rows || [];
        this.sink.total = r.total || 0;
        this.sink.page = r.page || p;
      } catch (e) { this.toast(e.message, 'err'); }
    },
    renderSinkTrend() {
      const el = this.$refs.sinkTrend;
      if (!el || !window.echarts) return;
      if (!this._sinkChart || this._sinkChart.getDom() !== el) {
        if (this._sinkChart) this._sinkChart.dispose();
        this._sinkChart = echarts.init(el, 'dark', { backgroundColor: 'transparent' });
      }
      const data = (this.sink.ov && this.sink.ov.trend) || [];
      const range = this.sinkFilter.range;
      // 数据点很少时（刚启用、或区间很短）要显示数据点：折线至少要两个点才画得出来，
      // 否则绘图区一片空白，看起来像功能坏了。
      const sparse = data.length <= 2;
      const fmt = (t) => {
        const d = new Date(t); const p = (x) => String(x).padStart(2, '0');
        return range === '1h' || range === '24h'
          ? `${p(d.getHours())}:${p(d.getMinutes())}`
          : `${p(d.getMonth() + 1)}-${p(d.getDate())}`;
      };
      this._sinkChart.setOption({
        grid: { left: 48, right: 20, top: 30, bottom: 28 },
        tooltip: { trigger: 'axis' },
        legend: { data: ['连接次数', '可读内容'], textStyle: { color: '#a3abb8' }, right: 0, top: 0 },
        xAxis: { type: 'category', data: data.map((d) => fmt(d.bucket)), axisLine: { lineStyle: { color: '#2a313a' } }, axisLabel: { color: '#7a838f' } },
        // 顶部留 15% 余量：否则单点情况下数据点正好压在网格顶线被裁掉一半
        yAxis: { type: 'value', max: (v) => (v.max <= 0 ? 1 : Math.ceil(v.max * 1.15)), splitLine: { lineStyle: { color: '#222831' } }, axisLabel: { color: '#7a838f' } },
        series: [
          // 两条线经常数值相同（全部可解密时完全重合），用「实心点 + 空心圈」区分，
          // 否则后画的线会把前面的盖住，看起来像少了一条线
          { name: '连接次数', type: 'line', smooth: true, showSymbol: sparse, symbol: 'circle', symbolSize: 7, data: data.map((d) => d.c), lineStyle: { width: 2, color: '#6b8fc7' }, areaStyle: { color: 'rgba(107,143,199,.14)' } },
          { name: '可读内容', type: 'line', smooth: true, showSymbol: sparse, symbol: 'emptyCircle', symbolSize: 13, data: data.map((d) => d.content), lineStyle: { width: 2, color: '#4bbf87' }, areaStyle: { color: 'rgba(75,191,135,.12)' } }
        ]
      }, true);
    },
    async sinkFlushNow() {
      try {
        const r = await this.api('/sink/flush', { method: 'POST' });
        this.toast(r.failed
          ? `落库暂时失败：${r.failed} 条将在下一轮自动重试`
          : `已落库：新增 ${r.inserted} 条、更新 ${r.updated} 条`, r.failed ? 'err' : 'ok');
        await this.loadSink();
      } catch (e) { this.toast(e.message, 'err'); }
    },
    async sinkPruneUnmapped() {
      if (!confirm('确定清理这些"未能归属到设备"的连接记录吗？\n（不含路由器本机；此操作不可撤销，可先导出 CSV 备份）')) return;
      try {
        const r = await this.api('/sink/prune-unmapped', { method: 'POST' });
        this.toast(`已清理未归属连接记录 ${r.deleted} 条`, 'ok');
        await this.loadSink();
      } catch (e) { this.toast(e.message, 'err'); }
    },
    async sinkClearAll() {
      if (!confirm('确定清空全部连接记录吗？\n（只影响本页的连接记录，设备台账与 IP 归属历史不受影响；此操作不可撤销）')) return;
      try {
        const r = await this.api('/sink/clear', { method: 'POST' });
        this.toast(`已清空连接记录 ${r.deleted} 条`, 'ok');
        await this.loadSink();
      } catch (e) { this.toast(e.message, 'err'); }
    },
    /** 流量详情表里点设备名：跳到该设备详情 */
    sinkOpenDevice(id) {
      if (id) this.openDevice(id);
    },
    sinkExpandAllRows() { this.sinkExpandAll = true; },
    sinkCollapseAll() { this.sinkExpandAll = false; this.sinkExpandId = null; },
    /** 清空筛选（保留时间区间，免得清完还要重新选一次） */
    sinkClearFilters() {
      const range = this.sinkFilter.range;
      this.sinkFilter = { deviceId: '', proto: '', host: '', ua: '', q: '', ja4: '', lport: '', outcome: '', decrypted: '', bodyKind: '', body: '', range };
      this.loadSink();
    },
    /** 点聚合表里的一行，把它当作筛选条件并回到列表 */
    sinkFilterBy(field, value) {
      this.sinkFilter[field] = value;
      this.loadSinkEvents(1);
    },
    /** 列表"主机与请求"下面那行的文本：请求行 + UA 合并，溢出按列宽省略 */
    reqLineText(r) {
      const req = (r.method || r.path)
        ? `${r.method || ''} ${r.path || ''}${r.query ? '?' + r.query : ''}`.trim()
        : '';
      return [req, r.ua].filter(Boolean).join(' · ');
    },
    /** 正文类型的中文名：列表徽章与详情都走这里，避免两处写法不一致 */
    bodyKindLabel(k) {
      return ({ json: 'JSON', form: '表单', multipart: '上传', xml: 'XML', text: '文本', binary: '二进制' })[k] || '';
    },
    /** 列表里的时间只显示首次出现，首次/最后都放在悬停提示里（这样每行始终只有一行） */
    timeTitle(r) {
      const first = `首次 ${this.fmtTime(r.ts)}`;
      return (r.last_ts && r.last_ts !== r.ts) ? `${first} ｜ 最后一次 ${this.fmtTime(r.last_ts)}` : first;
    },
    /** 指纹榜的悬停提示：带上对应的 JA3，便于和外部情报库对照 */
    fpTitle(f) {
      return f.ja3_sample ? `JA4 ${f.ja4} ｜ JA3 ${f.ja3_sample}` : `JA4 ${f.ja4}`;
    },
    /** 明细展开后的完整文本：把一条连接记录里能看到的全部内容摊开 */
    sinkDetailText(r) {
      const L = [];
      L.push(`时间：${this.fmtTime(r.ts)}${r.last_ts && r.last_ts !== r.ts ? '（最后一次 ' + this.fmtTime(r.last_ts) + '）' : ''}`);
      L.push(`次数：${r.hits}（去重窗口内合并）    耗时：${r.duration_ms == null ? '—' : r.duration_ms + ' ms'}    应答：${r.outcome || '—'}`);
      L.push(`设备：${r.device_name || '未归属'}    来源：${r.client_ip || '—'}${r.client_port ? ':' + r.client_port : ''}    本机端口：${r.lport}`);
      // decrypted 只表示"是否解密了 TLS"：明文 HTTP 本来就是可读的、值为 0，
      // 直接显示"已解明文：否"会让人以为正文没采到。所以这里按"内容可读性"来说。
      const readable = r.proto === 'http' ? '完整可读（明文 HTTP，无需解密）'
        : r.decrypted ? '已解出明文（TLS 已解密）'
          : r.proto === 'tls' ? '仅 SNI（未解密，看不到 URL 与正文）'
            : '未识别协议（只有首包 hex 预览）';
      L.push(`协议：${r.proto || '?'}    HTTP：${r.http_ver || '—'}    TLS：${r.tls_version || '—'}    ALPN：${r.alpn || '—'}    内容：${readable}`);
      // 套件信息只在两种情况下有：协商成功（tls_cipher）或读到过 ClientHello（客户端提供数）
      const tlsBits = [];
      if (r.tls_cipher) tlsBits.push(`协商套件 ${r.tls_cipher}`);
      if (r.tls_client_ciphers != null) tlsBits.push(`客户端提供 ${r.tls_client_ciphers} 个套件`);
      if (tlsBits.length) L.push(`TLS 细节：${tlsBits.join('    ')}`);
      // 指纹：JA4 稳定、推荐用它来判断"是不是同一个 App"（JA3 在 TLS 1.3 上会因扩展顺序打乱而变化）
      if (r.ja4) L.push(`客户端指纹：JA4 ${r.ja4}`);
      if (r.ja3) L.push(`              JA3 ${r.ja3}`);
      if (r.ja4) L.push('（JA4 由 ClientHello 的版本/套件/扩展/签名算法算出，不需解密即可获得；相同指纹通常意味着同一个客户端程序）');
      L.push(`主机（SNI / Host）：${r.host || '—'}`);
      if (r.method || r.path) L.push(`请求：${r.method || ''} ${r.path || ''}${r.query ? '?' + r.query : ''}`);
      if (r.ua) L.push(`User-Agent：${r.ua}`);
      if (r.referer) L.push(`来源页：${r.referer}`);
      if (r.tls_note) L.push(`备注：${r.tls_note}`);
      if (r.body_bytes != null) L.push(`正文长度：${r.body_bytes} 字节`);
      // 正文的"元信息"：类型/编码/字符集能解释"为什么正文看起来是那样"
      const bodyBits = [];
      if (r.body_kind) bodyBits.push(`类型 ${this.bodyKindLabel(r.body_kind)}`);
      if (r.content_type) bodyBits.push(`Content-Type ${r.content_type}`);
      if (r.content_encoding) bodyBits.push(`已解压 ${r.content_encoding}`);
      if (r.charset) bodyBits.push(`字符集 ${r.charset}`);
      if (bodyBits.length) L.push(`正文信息：${bodyBits.join('    ')}`);

      // 正文与头部都按"这条记录到底有没有 HTTP 请求"来判断：
      // 仅 SNI（未解密）、握手成功但没发请求、未知协议，这三种都没有请求可解析。
      const noHttpRequest = r.proto === 'tcp' || (!r.method && !r.path);
      const capBytes = Number((this.sinkStatus.capture || {}).body_bytes) || 0;
      const isHex = String(r.body_preview || '').startsWith('[hex] ');
      if (r.body_preview) {
        L.push(`正文预览${isHex ? '（二进制内容，以 hex 显示）' : ''}：\n${r.body_preview}`);
        if (r.body_bytes != null && capBytes && r.body_bytes > capBytes) {
          L.push(`（已截断：正文共 ${r.body_bytes} 字节，为控制体积只保留了前 ${capBytes} 字节，可在设置里调大「正文预览长度」）`);
        }
      } else if (noHttpRequest) {
        L.push('正文：该记录没有 HTTP 请求，因此不存在正文');
      } else if (r.body_bytes == null) {
        L.push('正文：该请求没有正文（GET / HEAD 一类不带正文的请求）');
      } else if (capBytes) {
        L.push('正文：未采集到（该次请求未在等待时间内送达正文）');
      } else {
        L.push('正文：未采集（当前设置里「采集正文预览」是关闭的）');
      }

      // 结构化字段：从正文里抽出的键值对，比原文更好扫。JSON 截断时可能解不出来，此时不显示。
      if (r.body_fields) {
        let pairs = null;
        try { pairs = JSON.parse(r.body_fields); } catch (e) { pairs = null; }
        if (pairs && typeof pairs === 'object') {
          const lines = Object.entries(pairs).map(([k, v]) => `  ${k} = ${v}`);
          L.push(`结构化字段（${lines.length} 项）：\n${lines.join('\n')}`);
        }
      } else if (r.body_kind && ['json', 'form', 'multipart'].includes(r.body_kind)) {
        L.push('结构化字段：无（正文多半被截断，解不出完整结构）');
      }

      if (r.headers_json) {
        try { L.push(`完整头部：\n${JSON.stringify(JSON.parse(r.headers_json), null, 2)}`); }
        catch (e) { L.push(`完整头部：\n${r.headers_json}`); }
      } else if (noHttpRequest) {
        const why = r.proto === 'tcp' ? '是未识别的协议'
          : (r.decrypted ? '没有可解析的请求' : '只读到 TLS 握手（未解密）');
        L.push(`完整头部：该记录${why}，没有 HTTP 请求，因此不存在请求头部`);
      } else {
        // 确实抓到过 HTTP 请求却没存头部：要么产生于开启之前，要么当前设置就是关的
        L.push(this.sinkStatus.capture && this.sinkStatus.capture.headers
          ? '完整头部：这条记录产生时尚未开启「采集完整头部」（只有开启之后新采集的记录才有）'
          : '完整头部：未采集（当前设置里「采集完整头部」是关闭的）');
      }
      return L.join('\n');
    },

    /* ---------- AdGuard 客户端管理 ---------- */
    async loadAgh() {
      try {
        this.agh = await this.api('/agh/clients');
        const names = new Set(this.agh.clients.map((c) => c.name));
        this.aghSel = this.aghSel.filter((n) => names.has(n));
      } catch (e) { this.toast(e.message, 'err'); }
    },
    openAghCreate() {
      this.aghForm = { name: '', deviceId: '' };
      this.aghPlan = null;
      this.aghIncludeUnknown = false;
      this.aghModal = true;
    },
    async toggleAghWrite() {
      const on = !this.isAghWriteOn;
      if (on && !confirm('确定允许本系统写回 AdGuard 吗？\n\n开启后「AdGuard 客户端」页会出现新建 / 修改 / 删除入口。每次写入前仍会先给你看差异预览。')) return;
      this.settings.allow_agh_write = on ? '1' : '0';
      await this.saveSettings();
      await this.loadAgh();
    },
    async toggleAghAutoSync() {
      const on = !this.isAghAutoSyncOn;
      if (on && !this.isAghWriteOn) { this.toast('请先打开上面的「允许写回 AdGuard」', 'err'); return; }
      if (on && !confirm('开启「自动定时同步」？\n\n本系统会按下面的间隔，自动把 AdGuard 客户端的 ids 调整为「主 MAC + 当前 IPv4」。\n- 只处理能唯一归属到本系统设备的客户端，其余不会改动\n- 只更新 ids，不会新建或删除客户端\n- 只移除明确失效的项，认不出来的地址保留\n- 每次变更都会写进任务记录，可随时关闭')) return;
      this.settings.agh_auto_sync = on ? '1' : '0';
      await this.saveSettings();
      await this.loadAgh();
    },
    /* 列表多选 */
    aghToggleSel(name) {
      const i = this.aghSel.indexOf(name);
      if (i >= 0) this.aghSel.splice(i, 1);
      else this.aghSel.push(name);
    },
    aghToggleSelAll() {
      this.aghSel = this.aghAllSelected ? [] : this.agh.clients.filter((c) => c.managed).map((c) => c.name);
    },
    /* 单个：预览与执行 */
    async previewAgh(name, deviceId) {
      if (!name) { this.toast('请先填写客户端名称', 'err'); return; }
      if (!deviceId) { this.toast('请先选择设备', 'err'); return; }
      this.aghBusy = true;
      try {
        this.aghIncludeUnknown = false;
        this.aghPlan = await this.api('/agh/clients/plan?name=' + encodeURIComponent(name) + '&deviceId=' + deviceId);
        this.aghModal = true;
      } catch (e) { this.toast(e.message, 'err'); }
      this.aghBusy = false;
    },
    /** 勾选/取消「一并清理未知项」后重新拉一次预览 */
    async reloadAghPlan() {
      if (!this.aghPlan) return;
      try {
        this.aghPlan = await this.api('/agh/clients/plan?name=' + encodeURIComponent(this.aghPlan.name)
          + '&deviceId=' + this.aghPlan.device_id + '&includeUnknown=' + this.aghIncludeUnknown);
      } catch (e) { this.toast(e.message, 'err'); }
    },
    aghTargetName() {
      const id = Number(this.aghPlan && this.aghPlan.device_id);
      const d = this.devices.find((x) => x.id === id);
      return d ? d.display_name : ('设备#' + id);
    },
    async applyAgh() {
      if (!this.aghPlan || (this.aghPlan.conflicts || []).length) return;
      this.aghBusy = true;
      try {
        const r = await this.api('/agh/clients', {
          method: 'POST',
          body: { name: this.aghPlan.name, deviceId: this.aghPlan.device_id, includeUnknown: this.aghIncludeUnknown }
        });
        this.toast((r.action === 'created' ? '已新建客户端「' : '已更新客户端「') + r.name + '」ids = ' + r.ids.join(', '), 'ok');
        this.aghModal = false;
        this.aghPlan = null;
        await this.loadAgh();
      } catch (e) { this.toast(e.message, 'err'); }
      this.aghBusy = false;
    },
    /* 批量 / 全量：预览与执行 */
    async openAghBatch(names) {
      this.aghBatchScope = Array.isArray(names) ? names.slice() : [];
      this.aghBusy = true;
      try {
        this.aghIncludeUnknown = false;
        const q = this.aghBatchScope.length ? ('?names=' + encodeURIComponent(this.aghBatchScope.join(','))) : '';
        this.aghBatch = await this.api('/agh/clients/plan-batch' + q);
        this.aghBatchModal = true;
      } catch (e) { this.toast(e.message, 'err'); }
      this.aghBusy = false;
    },
    async reloadAghBatch() {
      try {
        const q = (this.aghBatchScope.length ? ('names=' + encodeURIComponent(this.aghBatchScope.join(',')) + '&') : '')
          + 'includeUnknown=' + this.aghIncludeUnknown;
        this.aghBatch = await this.api('/agh/clients/plan-batch?' + q);
      } catch (e) { this.toast(e.message, 'err'); }
    },
    async applyAghBatch() {
      if (!this.aghBatch) return;
      const n = this.aghBatch.changed.length;
      if (!n) { this.toast('这些客户端都已是最新，无需写入', 'ok'); return; }
      if (!confirm(`确认向 AdGuard 写入以下变更？\n共 ${n} 个客户端（只更新 ids，不会新建或删除客户端）`)) return;
      this.aghBusy = true;
      try {
        const body = { includeUnknown: this.aghIncludeUnknown };
        if (this.aghBatchScope.length) body.names = this.aghBatchScope;
        const r = await this.api('/agh/clients/sync', { method: 'POST', body });
        let msg = `同步完成：更新 ${r.updated} 个客户端`;
        if (r.failed.length) msg += `，失败 ${r.failed.length} 个（${r.failed[0].error}）`;
        this.toast(msg, r.failed.length ? 'err' : 'ok');
        this.aghBatchModal = false;
        this.aghBatch = null;
        this.aghSel = [];
        this.aghStale = [];
        await this.loadAgh();
      } catch (e) { this.toast(e.message, 'err'); }
      this.aghBusy = false;
    },
    async deleteAgh(name) {
      if (!confirm(`确定删除 AdGuard 客户端「${name}」吗？\n（会直接修改你的 AdGuard 配置；本系统台账不受影响）`)) return;
      try {
        await this.api('/agh/clients/delete', { method: 'POST', body: { name } });
        this.toast(`已删除客户端「${name}」`, 'ok');
        await this.loadAgh();
      } catch (e) { this.toast(e.message, 'err'); }
    },
    async scanStale() {
      this.aghBusy = true;
      try {
        const r = await this.api('/agh/stale');
        this.aghStale = r.rows;
        const n = this.aghStale.length;
        this.toast(n ? `发现 ${n} 个客户端有可清理的 id` : '没有发现需要清理的 id', 'ok');
      } catch (e) { this.toast(e.message, 'err'); }
      this.aghBusy = false;
    },
    /** 清理：只传名字，ids 由服务端按规则重算（不采信前端数据） */
    async cleanStale(rows) {
      const list = Array.isArray(rows) ? rows : [];
      if (!list.length) return;
      const names = list.map((x) => x.name);
      const unk = list.reduce((a, x) => a + (x.unknown || []).length, 0);
      let tip = `确定清理这 ${names.length} 个客户端里明确失效的 id 吗？\n（只移除失效项；MAC 与当前 IP 一定保留）`;
      if (this.aghIncludeUnknown) tip += `\n\n注意：你已勾选「一并清理未知项」，这 ${unk} 个本系统认不出的地址也会被移除。`;
      if (!confirm(tip)) return;
      this.aghBusy = true;
      try {
        const r = await this.api('/agh/stale/clean', {
          method: 'POST',
          body: { names, include_unknown: this.aghIncludeUnknown }
        });
        this.toast(`已清理：更新 ${r.updated} 个客户端` + (r.failed.length ? `，失败 ${r.failed.length} 个` : ''), r.failed.length ? 'err' : 'ok');
        this.aghStale = [];
        await this.loadAgh();
      } catch (e) { this.toast(e.message, 'err'); }
      this.aghBusy = false;
    },
    async vacuumNow() {
      if (!confirm('立即整理数据库（VACUUM）？\n会短暂独占数据库，期间其它操作可能略慢。')) return;
      this.busy = true;
      try {
        const r = await this.api('/db/vacuum', { method: 'POST' });
        this.toast(`数据库整理完成：${r.beforeMB} MB → ${r.afterMB} MB`, 'ok');
        await this.loadDbInfo();
      } catch (e) { this.toast(e.message, 'err'); }
      this.busy = false;
    },
    async doCollect() {
      this.busy = true; this.busyCollect = true;
      try {
        const r = await this.api('/collect', { method: 'POST' });
        const st = r.stat;
        const b = st.backfilled || {};
        let msg = `采集完成：租约 ${st.leases} / IPv4 邻居 ${st.neigh4} / IPv6 邻居 ${st.neigh6}`;
        if (b.fixed) msg += `；回溯归属 ${b.fixed} 条日志`;
        if (b.remaining) msg += `（仍未归属 ${b.remaining} 条）`;
        this.toast(msg, 'ok');
        await this.loadDevices(); await this.loadOverview(); await this.loadJobs();
      } catch (e) { this.toast(e.message, 'err'); }
      this.busy = false; this.busyCollect = false;
    },
    async doIngest() {
      this.busy = true;
      try {
        const r = await this.api('/ingest', { method: 'POST', body: {} });
        const st = r.stat;
        let msg = `日志摄取完成：新增 ${st.inserted} 条`;
        if (st.duplicates) msg += `，重复跳过 ${st.duplicates} 条`;
        msg += `（扫描 ${st.scanned}）`;
        if (st.backfilled) msg += `；回溯归属 ${st.backfilled} 条`;
        if (st.unresolved) msg += `；本次未归属 ${st.unresolved} 条`;
        if (st.truncated) msg += `；已达单次抓取上限，更早历史未抓取`;
        this.toast(msg, st.unresolved ? 'info' : 'ok');
        await this.loadLogs(1); await this.loadOverview();
      } catch (e) { this.toast(e.message, 'err'); }
      this.busy = false;
    },
    async importAgh() {
      this.busy = true;
      try {
        const r = await this.api('/agh/import', { method: 'POST' });
        this.toast(`已读取并匹配 AdGuard 客户端 ${r.stat.imported}/${r.stat.total} 个（仅继承名称，不修改 AdGuard）`, 'ok');
        await this.loadDevices();
      } catch (e) { this.toast(e.message, 'err'); }
      this.busy = false;
    },

    /* ---------- 设备 ---------- */
    async openDevice(id) {
      if (!id) return;
      try {
        const r = await this.api('/devices/' + id);
        this.detail = r.device;
        this.view = 'device';
        this.loadDeviceTops(id);
      } catch (e) { this.toast(e.message, 'err'); }
    },
    /* 多选 */
    toggleSelect(id) {
      this.selected = this.selected.includes(id) ? this.selected.filter((x) => x !== id) : this.selected.concat(id);
    },
    toggleSelectAll() {
      const ids = this.filteredDevices.map((d) => d.id);
      this.selected = this.allSelected
        ? this.selected.filter((x) => !ids.includes(x))
        : [...new Set(this.selected.concat(ids))];
    },
    clearSelection() { this.selected = []; },
    /* 列表内联改名：点名称即可改，回车/失焦保存 */
    startEditName(d) {
      this.editingNameId = d.id;
      this.editingNameValue = d.name || '';
    },
    cancelEditName() { this.editingNameId = null; },
    async saveName(d) {
      if (this.editingNameId !== d.id) return;
      const val = (this.editingNameValue || '').trim();
      this.editingNameId = null;
      if (val === (d.name || '')) return;
      try {
        await this.api('/devices/' + d.id, { method: 'PUT', body: { name: val || null } });
        await this.loadDevices();
        if (this.view === 'device' && this.detail && this.detail.id === d.id) await this.openDevice(d.id);
      } catch (e) { this.toast(e.message, 'err'); }
    },
    /* 批量操作 */
    async applyBulk(patch) {
      if (!this.selected.length) return;
      try {
        const r = await this.api('/devices/bulk', { method: 'POST', body: { ids: this.selected, patch } });
        this.toast(`已更新 ${r.updated} 台设备`, 'ok');
        this.clearSelection();
        await this.loadDevices();
      } catch (e) { this.toast(e.message, 'err'); }
    },
    async applyBulkTag() {
      const t = (this.bulkTag || '').trim();
      if (!t) { this.toast('请输入标签', 'err'); return; }
      const targets = this.devices.filter((d) => this.selected.includes(d.id));
      try {
        for (const d of targets) {
          const tags = [...new Set([...(d.tags || []), t])];   // 标签是追加合并，不覆盖原有
          await this.api('/devices/' + d.id, { method: 'PUT', body: { tags } });
        }
        this.toast(`已为 ${targets.length} 台设备加上标签「${t}」`, 'ok');
        this.bulkTag = '';
        await this.loadDevices();
      } catch (e) { this.toast(e.message, 'err'); }
    },
    async bulkDelete() {
      if (!this.selected.length) return;
      if (!confirm(`确定删除选中的 ${this.selected.length} 台设备吗？\n（仅删除本系统的台账记录，不影响路由器与 AdGuard）`)) return;
      try {
        const r = await this.api('/devices/bulk-delete', { method: 'POST', body: { ids: this.selected } });
        this.toast(`已删除 ${r.deleted} 台设备`, 'ok');
        this.clearSelection();
        await this.loadDevices();
      } catch (e) { this.toast(e.message, 'err'); }
    },
    editDevice(d) {
      this.editing = {
        id: d.id, anchor: d.anchor, mac: d.mac, ip_count: d.ip_count, random_mac: d.random_mac,
        name: d.name || '', vendor: d.vendor || '', category: d.category || '', notes: d.notes || '',
        tagsText: (d.tags || []).join(', '),
        ignored: d.ignored ? 1 : 0
      };
      this.deviceModal = true;
    },
    async saveDevice() {
      const body = {
        name: this.editing.name, vendor: this.editing.vendor, category: this.editing.category,
        notes: this.editing.notes,
        tags: this.editing.tagsText.split(',').map((s) => s.trim()).filter(Boolean),
        ignored: this.editing.ignored ? 1 : 0
      };
      try {
        await this.api('/devices/' + this.editing.id, { method: 'PUT', body });
        this.deviceModal = false;
        this.toast('已保存', 'ok');
        await this.loadDevices();
        if (this.view === 'device') await this.openDevice(this.editing.id);
      } catch (e) { this.toast(e.message, 'err'); }
    },
    async removeDevice(d) {
      if (!confirm(`确定要删除设备「${d.name || d.anchor}」吗？其 IP 历史与本地日志归并关系也会移除（不影响 AdGuard 中的客户端）。`)) return;
      try {
        await this.api('/devices/' + d.id, { method: 'DELETE' });
        this.deviceModal = false;
        this.view = 'devices';
        await this.loadDevices();
        this.toast('已删除', 'ok');
      } catch (e) { this.toast(e.message, 'err'); }
    },
    openMerge(d) { this.mergeSource = d; this.mergeTargetId = ''; this.mergeModal = true; },
    async doMerge() {
      try {
        await this.api('/devices/merge', { method: 'POST', body: { sourceId: this.mergeSource.id, targetId: Number(this.mergeTargetId) } });
        this.mergeModal = false;
        this.toast('已合并', 'ok');
        await this.loadDevices();
      } catch (e) { this.toast(e.message, 'err'); }
    },
    async addIp() {
      if (!this.newIp) return;
      try {
        await this.api('/devices/' + this.detail.id + '/ips', { method: 'POST', body: { ip: this.newIp } });
        this.newIp = '';
        await this.openDevice(this.detail.id);
        this.toast('已添加 IP', 'ok');
      } catch (e) { this.toast(e.message, 'err'); }
    },
    async removeIp(ip) {
      try {
        await this.api('/devices/' + this.detail.id + '/ips?ip=' + encodeURIComponent(ip.ip), { method: 'DELETE' });
        await this.openDevice(this.detail.id);
      } catch (e) { this.toast(e.message, 'err'); }
    },
    viewLogsForDevice(id) {
      this.logFilter.deviceId = String(id);
      this.go('logs');                     // go('logs') 内部已执行 loadLogs(1)
    },

    /* ---------- 日志 ---------- */
    /** 组装日志筛选查询串（传 page 时才带分页参数，供导出复用） */
    buildLogQuery(page) {
      const rangeMs = { '1h': 3600000, '24h': 86400000, '7d': 604800000, '30d': 2592000000 }[this.logFilter.range] || 86400000;
      const qs = new URLSearchParams();
      if (this.logFilter.deviceId) qs.set('deviceId', this.logFilter.deviceId);
      if (this.logFilter.blocked !== '') qs.set('blocked', this.logFilter.blocked);
      if (this.logFilter.domain) qs.set('domain', this.logFilter.domain);
      if (this.logFilter.clientIp) qs.set('clientIp', this.logFilter.clientIp);
      qs.set('from', String(Date.now() - rangeMs));
      if (page) { qs.set('page', String(page)); qs.set('size', '50'); }
      return qs.toString();
    },
    async loadLogs(page) {
      const p = page || this.logs.page || 1;
      try {
        this.logs = await this.api('/logs?' + this.buildLogQuery(p));
        if (this.logFilter.deviceId === '__none__') await this.loadUnmappedIps();
        else this.unmappedIps = [];
      } catch (e) { this.toast(e.message, 'err'); }
    },
    async loadUnmappedIps() {
      try {
        const r = await this.api('/logs/unmapped-ips?range=' + this.logFilter.range + '&limit=100');
        this.unmappedIps = r.rows;
      } catch (e) { this.unmappedIps = []; }
    },
    openAssign(ip) {
      this.assignIpAddr = ip;
      this.assignDeviceId = '';
      this.assignMode = 'logs';
      this.assignModal = true;
    },
    /** 流量详情表里指派：同一个弹窗，但回填的是连接记录 */
    openSinkAssign(ip) {
      this.assignIpAddr = ip;
      this.assignDeviceId = '';
      this.assignMode = 'sink';
      this.assignModal = true;
    },
    async doAssign() {
      if (!this.assignDeviceId) { this.toast('请选择设备', 'err'); return; }
      const isSink = this.assignMode === 'sink';
      try {
        const r = await this.api(isSink ? '/sink/assign-ip' : '/logs/assign-ip',
          { method: 'POST', body: { ip: this.assignIpAddr, deviceId: Number(this.assignDeviceId) } });
        this.assignModal = false;
        this.toast(isSink
          ? `已把 ${r.ip} 指派给设备，回填 ${r.reassigned} 条连接记录`
          : `已把 ${r.ip} 指派给设备，回填 ${r.reassigned} 条日志`, 'ok');
        if (isSink) { await this.loadSink(); await this.loadDevices(); }
        else { await this.loadLogs(1); await this.loadOverview(); await this.loadDevices(); }
      } catch (e) { this.toast(e.message, 'err'); }
    },
    async pruneUnmapped() {
      if (!confirm('确定要删除所有"未能归属到任何设备"的日志吗？\n（不含路由器本机；此操作不可撤销，可先导出 CSV 备份）')) return;
      this.busy = true;
      try {
        const r = await this.api('/logs/prune-unmapped', { method: 'POST' });
        this.toast(`已清理未归属日志 ${r.deleted} 条`, 'ok');
        await this.loadLogs(1); await this.loadOverview();
      } catch (e) { this.toast(e.message, 'err'); }
      this.busy = false;
    },

    /* ---------- 连接 ---------- */
    openConn(c, kind) {
      if (c) {
        this.connForm = {
          id: c.id, kind: c.kind, name: c.name, host: c.host, port: c.port || 22, username: c.username,
          auth_type: c.auth_type || 'password', secret: '', passphrase: '',
          base_url: c.base_url, verify_tls: c.verify_tls ? 1 : 0, enabled: c.enabled ? 1 : 0, remark: c.remark || ''
        };
      } else {
        this.connForm = {
          id: null, kind: kind || 'ssh', name: '', host: '', port: 22, username: 'root',
          auth_type: 'password', secret: '', passphrase: '',
          base_url: 'http://192.168.1.1:3000', verify_tls: 1, enabled: 1, remark: ''
        };
      }
      this.connModal = true;
    },
    async saveConn() {
      const f = this.connForm;
      if (!f.name) { this.toast('请填写名称', 'err'); return; }
      const body = {
        kind: f.kind, name: f.name, enabled: f.enabled, username: f.username,
        auth_type: f.auth_type, verify_tls: f.verify_tls, remark: f.remark
      };
      if (f.kind === 'ssh') { body.host = f.host; body.port = f.port; }
      else { body.base_url = f.base_url; }
      if (f.secret) body.secret = f.secret;
      if (f.passphrase) body.passphrase = f.passphrase;
      try {
        if (f.id) await this.api('/connections/' + f.id, { method: 'PUT', body });
        else await this.api('/connections', { method: 'POST', body });
        this.connModal = false;
        this.toast('已保存', 'ok');
        await this.loadConnections();
      } catch (e) { this.toast(e.message, 'err'); }
    },
    async delConn(c) {
      if (!confirm(`删除连接「${c.name}」？`)) return;
      try {
        await this.api('/connections/' + c.id, { method: 'DELETE' });
        await this.loadConnections();
      } catch (e) { this.toast(e.message, 'err'); }
    },
    async testConn(c) {
      this.testResult = { ok: false, text: '测试中…' };
      this.testModal = true;
      try {
        const r = await this.api('/connections/' + c.id + '/test', { method: 'POST' });
        this.testResult = { ok: !!r.ok, text: r.ok ? (r.info ? JSON.stringify(r.info, null, 2) : r.output || '连接正常') : ('失败：' + (r.stderr || '未知错误')) };
      } catch (e) {
        this.testResult = { ok: false, text: e.message };
      }
    },

    /* ---------- 设置 ---------- */
    async saveSettings() {
      try {
        await this.api('/settings', { method: 'PUT', body: this.settings });
        this.settingsSaved = JSON.stringify(this.settings);
        this.toast('设置已保存（定时任务已重启）', 'ok');
      } catch (e) { this.toast(e.message, 'err'); }
    },
    async updateOui() {
      this.busy = true;
      this.toast('正在拉取厂商库…', 'info');
      try {
        const r = await this.api('/oui/update', { method: 'POST' });
        this.toast(`厂商库已更新：${r.result.source}（${this.fmtNum(r.result.count)} 条）`, 'ok');
        await this.loadOui(); await this.loadDevices();
      } catch (e) { this.toast(e.message, 'err'); }
      this.busy = false;
    }
  }
});

/* 可搜索的设备选择器：替代设备多时的 <select>（设备多时用下拉列表很难找到）。
   用法：<device-picker v-model="someId" :devices="devices" :exclude="[id]"/> */
app.component('device-picker', {
  props: {
    modelValue: { type: String, default: '' },
    devices: { type: Array, default: () => [] },
    exclude: { type: Array, default: () => [] },
    placeholder: { type: String, default: '搜索设备：名称 / 主机名 / MAC / IP / 厂商' }
  },
  emits: ['update:modelValue'],
  data() { return { open: false, query: '', hi: 0 }; },
  watch: {
    // 关键词一变，候选列表整体换了一批，旧的高亮下标可能已越界（会导致按 Enter 选不中）
    query() { this.hi = 0; }
  },
  computed: {
    selected() {
      const id = Number(this.modelValue);
      return this.devices.find((d) => d.id === id) || null;
    },
    candidates() {
      const q = this.query.trim().toLowerCase();
      const base = this.devices.filter((d) => !this.exclude.includes(d.id));
      if (!q) return base.slice(0, 40);            // 未输入时先列出最近活跃的若干台
      return base.filter((d) =>
        (d.display_name || '').toLowerCase().includes(q) ||
        (d.name || '').toLowerCase().includes(q) ||
        (d.suggested_name || '').toLowerCase().includes(q) ||
        (d.mac || '').toLowerCase().includes(q) ||
        (d.anchor || '').toLowerCase().includes(q) ||
        (d.vendor || '').toLowerCase().includes(q) ||
        (d.current_ips || []).some((ip) => ip.includes(q)) ||
        (d.macs || []).some((m) => m.includes(q))
      ).slice(0, 40);
    }
  },
  methods: {
    label(d) { return d.display_name || d.anchor || ('设备#' + d.id); },
    sub(d) {
      const parts = [];
      const mac = d.mac || d.anchor;
      if (mac) parts.push(mac);
      if (d.current_ip) parts.push(d.current_ip);
      if (d.vendor) parts.push(d.vendor);
      return parts.join(' · ');
    },
    openList() {
      if (this.open) return;
      this.open = true;
      this.query = '';
      this.hi = Math.max(0, this.candidates.findIndex((d) => this.selected && d.id === this.selected.id));
      this.$nextTick(() => { if (this.$refs.q) this.$refs.q.focus(); });
      this.scrollHi();
      this._out = (e) => { if (this.$el && !this.$el.contains(e.target)) this.close(); };
      document.addEventListener('mousedown', this._out);
    },
    close() {
      this.open = false;
      if (this._out) { document.removeEventListener('mousedown', this._out); this._out = null; }
    },
    pick(d) { this.$emit('update:modelValue', String(d.id)); this.close(); },
    move(step) {
      const n = this.candidates.length;
      if (!n) return;
      this.hi = (this.hi + step + n) % n;
      this.scrollHi();
    },
    /** 键盘移动高亮时把该项滚进可视区（列表高度有限，否则高亮会跑到看不见的地方） */
    scrollHi() {
      this.$nextTick(() => {
        const list = this.$refs.list;
        const el = list && list.querySelector('.picker-item.hi');
        if (el && el.scrollIntoView) el.scrollIntoView({ block: 'nearest' });
      });
    },
    confirm() { const d = this.candidates[this.hi]; if (d) this.pick(d); },
    clear() { this.$emit('update:modelValue', ''); }
  },
  beforeUnmount() { if (this._out) document.removeEventListener('mousedown', this._out); },
  template: `
    <div class="picker">
      <div class="picker-head" @click="openList()">
        <input v-if="open" ref="q" class="input picker-input" v-model="query" :placeholder="placeholder"
               @keydown.down.prevent="move(1)" @keydown.up.prevent="move(-1)"
               @keydown.enter.prevent="confirm()" @keydown.esc.prevent="close()">
        <template v-else>
          <span v-if="selected" class="picker-value">{{ label(selected) }}</span>
          <span v-else class="picker-ph">{{ placeholder }}</span>
        </template>
        <span v-if="selected && !open" class="picker-x" title="清除" @click.stop="clear()">×</span>
        <span v-else class="picker-arrow">▾</span>
      </div>
      <div v-if="open" ref="list" class="picker-list">
        <div v-if="!candidates.length" class="picker-empty">无匹配设备</div>
        <div v-for="(d,i) in candidates" :key="d.id" class="picker-item" :class="{ hi: i===hi }"
             @mouseenter="hi=i" @mousedown.prevent="pick(d)">
          <div class="picker-name">{{ label(d) }}
            <span class="badge danger" v-if="d.ignored">已忽略</span>
          </div>
          <div class="picker-sub mono">{{ sub(d) }}</div>
        </div>
      </div>
    </div>`
});

// 内联改名时自动聚焦并选中
app.directive('focus', {
  mounted(el) { el.focus(); if (el.select) el.select(); }
});

app.mount('#app');
