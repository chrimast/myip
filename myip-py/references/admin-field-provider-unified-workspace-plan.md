# Admin Field/Provider Unified Workspace Implementation Plan

> **For Hermes:** Use subagent-driven-development skill to implement this plan task-by-task.

**Goal:** 把 `/admin` 里的评分字段、非评分字段、Provider 视图、Provider 卡片整合成一个更容易浏览和编辑的“字段与数据源映射”工作区，同时保持现有配置结构简单稳定。

**Architecture:** 先做前端可读性整合，不改变公开 `/api/ip` 响应和 provider 运行语义。继续使用现有 `/api/admin/fields`、`/api/admin/providers`、`/api/admin/field-mappings` 数据；在 `admin.html` 中把字段和 Provider 从大卡片改成摘要优先、详情可展开、可筛选的工作区。Provider 管理里的“Provider 卡片”不再独立重复展示，改为和字段映射共享一个 Provider 覆盖摘要。

**Tech Stack:** FastAPI 静态 `app/static/admin.html`，pytest `tests/test_admin.py`，Docker Compose dev service `docker-compose.dev.yml`。

---

## Current diagnosis

- 现有页面已有 `4. 字段与数据源映射`，但字段卡片仍一次性展开大量内容，Provider 视图和 Provider 管理里的“Provider 卡片”信息重复。
- `Provider 配置` 负责启用/顺序/超时/运行设置；`字段与数据源映射` 应负责“哪些字段从哪些 Provider/raw paths 来”。两者不要混合成一个存储模型。
- 用户建议把 Provider 卡片也整合在一起：应把原 `#providers` 的卡片能力迁移/并入 mapping workspace 的 Provider 视图，保留 Provider 管理区专注配置控件。

## Acceptance criteria

- `/admin` 中字段浏览默认是摘要行，不再默认展开几十个大字段卡片。
- 字段仍分为 `评分字段` / `非评分字段`，但每行只显示：字段名、中文标签、评分/展示标记、Provider 来源数量、默认/后台映射。
- 字段详情用 `<details data-field-detail>` 收起，里面保留 provider paths、评分规则、JSON 映射编辑器、添加来源小表单。
- 增加 `字段筛选`：文本搜索、评分/非评分/自定义筛选、Provider 筛选。
- `Provider 视图` 改为 `Provider 覆盖摘要`：每个 Provider 展示启用/停用、自定义状态、覆盖字段数、评分字段数、关键身份字段覆盖情况，并用 `<details data-provider-field-details>` 展开 raw paths。
- `Provider 管理` 右侧独立“Provider 卡片”删除或改成跳转提示，避免与 Provider 视图重复；Provider 信息集中在 mapping workspace。
- 增加 `映射问题提示`，优先提示：无来源字段、关键评分字段只有一个来源、后台覆盖映射、启用但没有映射贡献的 Provider。
- 不新增 public API 字段开关，不改变 `/api/ip` 响应结构，不改变 provider runtime extraction。

---

## Task 1: Add shell assertions for unified legibility hooks

**Objective:** 用测试固定目标 UX，而不是固定 DOM/CSS 细节。

**Files:**
- Modify: `tests/test_admin.py::test_admin_page_serves_provider_management_shell`

**Step 1: Write failing test**

Add assertions near existing mapping-workspace assertions:

```python
assert "字段筛选" in body
assert "data-field-filter" in body
assert "data-field-summary-row" in body
assert "data-field-detail" in body
assert "Provider 覆盖摘要" in body
assert "data-provider-coverage-summary" in body
assert "data-provider-field-details" in body
assert "映射问题提示" in body
assert "data-mapping-issues" in body
assert "data-provider-management-summary-link" in body
```

**Step 2: Run test to verify failure**

Run:

```bash
docker compose -f docker-compose.dev.yml exec -T -e PYTHONPATH=/app myip python -m pytest tests/test_admin.py::test_admin_page_serves_provider_management_shell -q
```

Expected: FAIL on the first missing marker.

---

## Task 2: Simplify Provider 管理 card duplication

**Objective:** Provider 管理只保留配置控件，把 Provider 信息卡片入口指向统一工作区。

**Files:**
- Modify: `app/static/admin.html`
- Test: `tests/test_admin.py::test_admin_page_serves_provider_management_shell`

**Step 1: Update static shell**

Replace the right column currently containing:

```html
<h3>Provider 卡片</h3>
<div id="providers" class="grid"></div>
```

with an operator-facing summary/link card:

```html
<div class="card" data-provider-management-summary-link>
  <h3>Provider 覆盖摘要已整合</h3>
  <p>Provider 的启用状态、覆盖字段、关键身份字段和 raw path 明细统一放在下方“字段与数据源映射”的 Provider 视图中。</p>
  <a class="pill" href="#mapping-workspace">查看 Provider 覆盖摘要</a>
</div>
```

Keep `data-provider-card` string in JS-generated Provider view or tests should be updated to assert the new provider coverage markers instead of the old duplicated panel.

**Step 2: Verify focused shell test**

Run the same focused command. Expected: if only old `Provider 卡片` assertion fails, update it to accept the new copy `Provider 覆盖摘要已整合`.

---

## Task 3: Render field rows summary-first

**Objective:** 把 always-expanded `fieldCard()` 改成 summary row + collapsed details。

**Files:**
- Modify: `app/static/admin.html`

**Step 1: Add filter controls above field cards**

In `data-field-view`, before `#field-cards`, add:

```html
<div class="card" data-field-filter>
  <h3>字段筛选</h3>
  <input data-field-filter-text placeholder="搜索字段名或标签">
  <select data-field-filter-kind>
    <option value="all">全部字段</option>
    <option value="scoring">评分字段</option>
    <option value="display">非评分字段</option>
    <option value="custom">自定义字段</option>
  </select>
  <select data-field-filter-provider>
    <option value="all">全部 Provider</option>
  </select>
</div>
<div class="card" data-mapping-issues>
  <h3>映射问题提示</h3>
  <div id="mapping-issues">加载中</div>
</div>
```

**Step 2: Replace `fieldCard(field)` output shape**

Use a compact row wrapper:

```js
return `<div class="card field-summary-row" data-field-summary-row="${esc(field.field)}" data-field-card="${esc(field.field)}" data-field-name="${esc(field.field)}" data-field-label="${esc(field.label)}" data-field-scoring="${field.scoring ? 'true' : 'false'}" data-field-custom="${field.custom ? 'true' : 'false'}" data-field-providers="${esc(Object.keys(field.providers || {}).join(','))}" ${field.scoring ? `data-scoring-field="${esc(field.field)}"` : ''}>
  <div class="field-summary-line">
    <strong>${esc(field.display_name || field.field)}</strong>
    <span class="pill">${esc(field.label)}</span>
    ${field.scoring ? '<span class="pill ok">评分字段</span>' : '<span class="pill">非评分字段</span>'}
    <span class="pill">来源 ${Object.keys(field.providers || {}).length}</span>
    <span class="pill">${field.mapping_source === 'admin' ? '后台映射' : '默认映射'}</span>
  </div>
  <details data-field-detail="${esc(field.field)}" data-field-mapping-editor="${esc(field.field)}">
    <summary>展开字段映射、评分说明和编辑器</summary>
    ... keep existing mapping rows, scoring rule, add-source controls, textarea ...
  </details>
</div>`;
```

**Step 3: Preserve editor behavior**

Keep all existing hooks:
- `data-field-mapping`
- `data-field-provider-select`
- `data-field-path-input`
- `data-add-field-path`
- `data-field-mapping-json`
- `data-field-mapping-editor`

---

## Task 4: Add frontend filtering

**Objective:** 支持轻量客户端过滤，不新增 API。

**Files:**
- Modify: `app/static/admin.html`

**Step 1: Populate Provider filter options**

In `renderFieldCards(fields)` after rendering HTML:

```js
const providerFilter = document.querySelector('[data-field-filter-provider]');
if (providerFilter) {
  const current = providerFilter.value || 'all';
  const providers = [...new Set(fields.flatMap(field => Object.keys(field.providers || {})))].sort();
  providerFilter.innerHTML = '<option value="all">全部 Provider</option>' + providers.map(provider => `<option value="${esc(provider)}">${esc(provider)}</option>`).join('');
  providerFilter.value = providers.includes(current) ? current : 'all';
}
```

**Step 2: Add `applyFieldFilters()`**

```js
function applyFieldFilters() {
  const text = (document.querySelector('[data-field-filter-text]')?.value || '').trim().toLowerCase();
  const kind = document.querySelector('[data-field-filter-kind]')?.value || 'all';
  const provider = document.querySelector('[data-field-filter-provider]')?.value || 'all';
  document.querySelectorAll('[data-field-summary-row]').forEach(row => {
    const searchable = `${row.dataset.fieldName || ''} ${row.dataset.fieldLabel || ''}`.toLowerCase();
    const providers = (row.dataset.fieldProviders || '').split(',').filter(Boolean);
    const matchesText = !text || searchable.includes(text);
    const matchesKind = kind === 'all' || (kind === 'scoring' && row.dataset.fieldScoring === 'true') || (kind === 'display' && row.dataset.fieldScoring !== 'true') || (kind === 'custom' && row.dataset.fieldCustom === 'true');
    const matchesProvider = provider === 'all' || providers.includes(provider);
    row.style.display = matchesText && matchesKind && matchesProvider ? '' : 'none';
  });
}
```

**Step 3: Wire event listeners**

After rendering field cards:

```js
document.querySelectorAll('[data-field-filter-text], [data-field-filter-kind], [data-field-filter-provider]').forEach(input => input.addEventListener('input', applyFieldFilters));
applyFieldFilters();
```

---

## Task 5: Render Provider coverage summaries

**Objective:** 把 Provider 视图升级成覆盖摘要，并承接原 Provider 卡片信息。

**Files:**
- Modify: `app/static/admin.html`

**Step 1: Replace `renderMappingProviderView(providers)` rows**

For each provider, calculate:

```js
const contributedFields = fields.filter(field => (field.providers || {})[provider.id]);
const scoringCount = contributedFields.filter(field => field.scoring).length;
const identityFields = ['asn_owner','org','isp','asn_domain','org_domain'].filter(fieldName => contributedFields.some(field => field.field === fieldName));
```

Render:

```js
return `<div class="card" data-provider-card="${esc(provider.id)}" data-provider-coverage-summary="${esc(provider.id)}">
  <h3>${esc(provider.order)}. ${esc(provider.id)}${provider.custom ? ' · 自定义' : ''}</h3>
  <p>
    <span class="pill ${provider.enabled ? 'ok' : ''}">${provider.enabled ? '启用' : '停用'}</span>
    <span class="pill">覆盖字段 ${contributedFields.length}</span>
    <span class="pill">评分字段 ${scoringCount}</span>
    <span class="pill">身份字段 ${identityFields.length ? identityFields.join(', ') : '无'}</span>
  </p>
  <p class="muted">${esc(provider.endpoint || '')}</p>
  <details data-provider-field-details="${esc(provider.id)}">
    <summary>展开 raw path 明细</summary>
    ${rows}
  </details>
</div>`;
```

**Step 2: Add empty states**

If no fields map to a provider, show `暂未参与字段映射` inside details and later surface it in mapping issues.

---

## Task 6: Add mapping issue hints

**Objective:** 给管理员一个可操作的问题列表。

**Files:**
- Modify: `app/static/admin.html`

**Step 1: Add `renderMappingIssues(fields, providers)`**

Rules:

```js
function renderMappingIssues(fields, providers) {
  const issues = [];
  fields.forEach(field => {
    const providerCount = Object.keys(field.providers || {}).length;
    if (!providerCount) issues.push(`${field.field} 没有 Provider 来源`);
    if (field.scoring && providerCount === 1) issues.push(`${field.field} 评分字段只有一个来源`);
    if (field.mapping_source === 'admin') issues.push(`${field.field} 使用后台覆盖映射`);
  });
  (providers || []).filter(provider => provider.enabled).forEach(provider => {
    const contributes = fields.some(field => (field.providers || {})[provider.id]);
    if (!contributes) issues.push(`${provider.id} 已启用但没有映射贡献`);
  });
  const node = document.getElementById('mapping-issues');
  if (node) node.innerHTML = issues.length ? issues.map(issue => `<span class="pill warn">${esc(issue)}</span>`).join('') : '<span class="ok">暂无明显映射问题</span>';
}
```

**Step 2: Call it from render functions**

Call `renderMappingIssues(window.adminFields || [], window.adminProviders || [])` at the end of `renderFieldCards()` and `renderProviders()`.

---

## Task 7: Verify all admin behavior remains intact

**Objective:** 确认这是纯前端/UX 整合，没有破坏后台配置、字段映射、custom provider flows。

**Commands:**

```bash
docker compose -f docker-compose.dev.yml exec -T -e PYTHONPATH=/app myip python -m pytest tests/test_admin.py::test_admin_page_serves_provider_management_shell -q
docker compose -f docker-compose.dev.yml exec -T -e PYTHONPATH=/app myip python -m pytest tests/test_admin.py -q
docker compose -f docker-compose.dev.yml exec -T -e PYTHONPATH=/app myip python -m pytest -q
docker compose -f docker-compose.dev.yml ps
```

Expected:
- focused shell test passes.
- all admin tests pass.
- full suite passes.
- dev service remains running; do not run `docker compose down`.

---

## Non-goals

- 不做首页字段展示配置。
- 不做 public `/api/ip` 响应字段开关。
- 不改变 ASN owner / org / ISP 的 runtime 提取逻辑。
- 不改变 custom provider 是否进入公开接口的双门控逻辑。
- 不创建新的 `mapping_workspace` 存储结构；继续使用 `custom_providers`、`custom_fields`、`field_mappings`。
