const GRAPH_URL = "capec-visualization/data/correlation_graph.json";
const CATALOG_URL = "heuristics/catalog.json";

const state = {
    graph: null,
    catalog: null,
    query: "",
    type: "all",
    stride: null,
    selected: null,
    tab: "related",
};

const els = {
    strideGrid: document.getElementById("strideGrid"),
    searchInput: document.getElementById("searchInput"),
    typeFilter: document.getElementById("typeFilter"),
    statsLine: document.getElementById("statsLine"),
    results: document.getElementById("results"),
    listTitle: document.getElementById("listTitle"),
    detailPane: document.getElementById("detailPane"),
};

function strideName(letter) {
    const found = state.graph?.stride.find((item) => item.id === letter);
    return found ? `${letter} · ${found.name}` : letter;
}

function escapeHtml(value) {
    return String(value ?? "")
        .replaceAll("&", "&amp;")
        .replaceAll("<", "&lt;")
        .replaceAll(">", "&gt;")
        .replaceAll('"', "&quot;");
}

function strideChips(letters, clickable = true) {
    return (letters || [])
        .map((letter) => {
            const label = strideName(letter);
            if (!clickable) {
                return `<span class="chip ${letter}">${escapeHtml(label)}</span>`;
            }
            return `<button class="chip ${letter}" data-open="STRIDE-${letter}">${escapeHtml(label)}</button>`;
        })
        .join("");
}

function idChips(kind, ids, limit = 24) {
    const prefix = kind.toUpperCase();
    return (ids || [])
        .slice(0, limit)
        .map((id) => {
            const label = kind === "cve" ? id : `${prefix}-${id}`;
            return `<button class="chip" data-open="${escapeHtml(label)}">${escapeHtml(label)}</button>`;
        })
        .join("");
}

function matchesQuery(text, query) {
    if (!query) return true;
    return text.toLowerCase().includes(query);
}

function itemRecord(kind, id, node) {
    const prefix = kind.toUpperCase();
    const label = kind === "cve" ? String(id) : `${prefix}-${id}`;
    const search = [
        kind,
        id,
        label,
        node.name || "",
        node.title || "",
        node.summary || "",
        (node.stride || []).join(" "),
        (node.cwes || []).map((value) => `CWE-${value} ${value}`).join(" "),
        (node.capecs || []).map((value) => `CAPEC-${value} ${value}`).join(" "),
        (node.cves || []).join(" "),
    ]
        .join(" ")
        .toLowerCase();
    return {
        kind,
        id: String(id),
        title: node.name || node.title || label,
        summary: node.summary || "",
        stride: node.stride || [],
        search,
        node,
    };
}

function allItems() {
    const { capecs, cwes, cves } = state.graph;
    const items = [];
    for (const [id, node] of Object.entries(capecs)) items.push(itemRecord("capec", id, node));
    for (const [id, node] of Object.entries(cwes)) items.push(itemRecord("cwe", id, node));
    for (const [id, node] of Object.entries(cves)) items.push(itemRecord("cve", id, node));
    return items;
}

function filteredItems() {
    const query = state.query.trim().toLowerCase();
    return allItems().filter((item) => {
        if (state.type !== "all" && item.kind !== state.type) return false;
        if (state.stride && !item.stride.includes(state.stride)) return false;
        return matchesQuery(item.search, query);
    });
}

function parseOpenToken(token) {
    const value = (token || "").trim().toUpperCase();
    if (value.startsWith("STRIDE-")) return { kind: "stride", id: value.replace("STRIDE-", "") };
    if (value.startsWith("CAPEC-")) return { kind: "capec", id: value.replace("CAPEC-", "").replace(/^0+/, "") || "0" };
    if (value.startsWith("CWE-")) return { kind: "cwe", id: value.replace("CWE-", "").replace(/^0+/, "") || "0" };
    if (value.startsWith("CVE-")) return { kind: "cve", id: value };
    return null;
}

function selectFromHash() {
    const token = decodeURIComponent(location.hash.replace(/^#/, ""));
    const parsed = parseOpenToken(token);
    if (!parsed) return;
    if (parsed.kind === "stride") {
        state.stride = parsed.id;
        state.selected = { kind: "stride", id: parsed.id };
        state.tab = "related";
        return;
    }
    state.selected = parsed;
    state.tab = "related";
    const related = relatedFor(parsed.kind, parsed.id);
    if (state.stride && related && !(related.stride || []).includes(state.stride)) {
        state.stride = null;
    }
}

function setHash(kind, id) {
    const token = kind === "stride" ? `STRIDE-${id}` : kind === "cve" ? id : `${kind.toUpperCase()}-${id}`;
    history.replaceState(null, "", `#${token}`);
}

function renderStrideCards() {
    els.strideGrid.innerHTML = state.graph.stride
        .map(
            (item) => `
        <button class="stride-card ${state.stride === item.id ? "active" : ""}" style="--color: var(--${item.id})" data-stride="${item.id}">
            <strong>${item.id} · ${escapeHtml(item.name)}</strong>
            <span>${item.capecCount} CAPEC · ${item.cweCount} CWE · ${item.cveCount} CVE</span>
        </button>`
        )
        .join("");
}

function renderResults() {
    const items = filteredItems();
    els.listTitle.textContent = `${items.length} resultado(s)`;
    const slice = items.slice(0, 250);
    els.results.innerHTML = slice
        .map((item) => {
            const selected =
                state.selected && state.selected.kind === item.kind && String(state.selected.id) === String(item.id);
            return `
            <button class="result ${selected ? "selected" : ""}" data-kind="${item.kind}" data-id="${escapeHtml(item.id)}">
                <span class="kind">${item.kind.toUpperCase()}</span>
                <span>
                    <strong>${item.kind === "cve" ? escapeHtml(item.id) : `${item.kind.toUpperCase()}-${escapeHtml(item.id)}`}</strong><br>
                    ${escapeHtml(item.title)}
                </span>
                <span class="meta">${(item.stride || []).join(" ")}</span>
            </button>`;
        })
        .join("");
    if (items.length > 250) {
        els.results.insertAdjacentHTML("beforeend", `<p class="meta">Mostrando 250 de ${items.length}. Refine a busca.</p>`);
    }
}

function relatedFor(kind, id) {
    const { capecs, cwes, cves } = state.graph;
    if (kind === "stride") {
        const capecIds = Object.keys(capecs).filter((key) => (capecs[key].stride || []).includes(id));
        const cweIds = Object.keys(cwes).filter((key) => (cwes[key].stride || []).includes(id));
        const cveIds = Object.keys(cves).filter((key) => (cves[key].stride || []).includes(id));
        return { capecs: capecIds, cwes: cweIds, cves: cveIds, stride: [id] };
    }
    if (kind === "capec") {
        const node = capecs[id];
        if (!node) return null;
        const cveIds = [];
        for (const cweId of node.cwes || []) {
            for (const cveId of cwes[cweId]?.cves || []) {
                if (!cveIds.includes(cveId)) cveIds.push(cveId);
            }
        }
        return { capecs: [id], cwes: node.cwes || [], cves: cveIds, stride: node.stride || [], node };
    }
    if (kind === "cwe") {
        const node = cwes[id];
        if (!node) return null;
        return { capecs: node.capecs || [], cwes: [id], cves: node.cves || [], stride: node.stride || [], node };
    }
    const node = cves[id];
    if (!node) return null;
    return { capecs: node.capecs || [], cwes: node.cwes || [], cves: [id], stride: node.stride || [], node };
}

function catalogFor(related) {
    if (!state.catalog || !related) return [];
    const strideSet = new Set(related.stride || []);
    const capecSet = new Set((related.capecs || []).map(String));
    const cweSet = new Set((related.cwes || []).map(String));
    const isStrideView = state.selected?.kind === "stride";
    const rows = [];
    for (const category of state.catalog.categories) {
        if (isStrideView && category.id !== state.selected.id) continue;
        if (!isStrideView && strideSet.size && !strideSet.has(category.id) && !category.indicators.some((ind) =>
            ind.capecs.some((value) => capecSet.has(String(value))) || ind.cwes.some((value) => cweSet.has(String(value)))
        )) {
            continue;
        }
        for (const indicator of category.indicators) {
            const capecHit = indicator.capecs.some((value) => capecSet.has(String(value)));
            const cweHit = indicator.cwes.some((value) => cweSet.has(String(value)));
            if (isStrideView || capecHit || cweHit) {
                rows.push({ ...indicator, stride: category.id, strideName: category.name, astFocus: category.astFocus, codeQuestion: category.codeQuestion });
            }
        }
    }
    if (!rows.length) {
        for (const category of state.catalog.categories) {
            if (!strideSet.has(category.id)) continue;
            for (const indicator of category.indicators) {
                rows.push({ ...indicator, stride: category.id, strideName: category.name, astFocus: category.astFocus, codeQuestion: category.codeQuestion });
            }
        }
    }
    return rows;
}

function renderDetail() {
    if (!state.selected) {
        els.detailPane.innerHTML = `<p class="placeholder">Selecione um item para ver CAPEC, CWE, CVE e como detectar no código.</p>`;
        return;
    }
    const related = relatedFor(state.selected.kind, state.selected.id);
    if (!related) {
        els.detailPane.innerHTML = `<p class="placeholder">Item não encontrado no grafo.</p>`;
        return;
    }
    const node = related.node;
    let heading = "";
    let summary = "";
    if (state.selected.kind === "stride") {
        const meta = state.graph.stride.find((item) => item.id === state.selected.id);
        heading = `${meta.id} · ${meta.name}`;
        summary = meta.description;
    } else if (state.selected.kind === "cve") {
        heading = state.selected.id;
        summary = node?.title || node?.summary || "";
    } else {
        heading = `${state.selected.kind.toUpperCase()}-${state.selected.id} · ${node?.name || ""}`;
        summary = node?.summary || "";
    }

    const heuristics = catalogFor(related);
    const relatedView = `
        <div class="chips">${strideChips(related.stride)}</div>
        <h3>CAPEC (${related.capecs.length})</h3>
        <div class="chips">${idChips("capec", related.capecs, 40) || "<span class='meta'>nenhum</span>"}</div>
        <h3>CWE (${related.cwes.length})</h3>
        <div class="chips">${idChips("cwe", related.cwes, 40) || "<span class='meta'>nenhum</span>"}</div>
        <h3>CVE (${related.cves.length})</h3>
        <div class="chips">${idChips("cve", related.cves, 40) || "<span class='meta'>nenhum</span>"}</div>
        ${related.cves.length > 40 ? `<p class="meta">Mostrando 40 de ${related.cves.length} CVEs.</p>` : ""}
        ${node?.parents?.length ? `<p class="meta">Pais CAPEC: ${node.parents.map((id) => "CAPEC-" + id).join(", ")}</p>` : ""}
    `;

    const codeView = heuristics.length
        ? heuristics
              .map(
                  (item) => `
            <article class="heuristic">
                <p class="severity ${item.severity}">${item.severity} · ${item.stride} ${escapeHtml(item.strideName)}</p>
                <h3>${escapeHtml(item.title)}</h3>
                <p>${escapeHtml(item.description)}</p>
                <p class="meta">${escapeHtml((item.astFocus || []).join(" · "))}</p>
                <div class="chips">${idChips("cwe", item.cwes)}${idChips("capec", item.capecs)}</div>
            </article>`
              )
              .join("")
        : `<p class="meta">Ainda não há heurística AST específica para este recorte. Use os sinks/sources da categoria STRIDE.</p>`;

    els.detailPane.innerHTML = `
        <h2>${escapeHtml(heading)}</h2>
        <p>${escapeHtml(summary)}</p>
        ${node?.severity ? `<p class="meta">Severidade CAPEC: ${escapeHtml(node.severity)} · Likelihood: ${escapeHtml(node.likelihood || "n/a")}</p>` : ""}
        <div class="tabs">
            <button data-tab="related" class="${state.tab === "related" ? "active" : ""}">Relacionados</button>
            <button data-tab="code" class="${state.tab === "code" ? "active" : ""}">Como achar no código</button>
        </div>
        ${state.tab === "code" && heuristics[0] ? `<p><strong>${escapeHtml(heuristics[0].codeQuestion)}</strong></p><p class="meta">${escapeHtml(state.catalog.intro)}</p>` : ""}
        ${state.tab === "related" ? relatedView : codeView}
    `;
}

function render() {
    const stats = state.graph.meta.stats;
    els.statsLine.textContent = `${stats.capecs} CAPEC · ${stats.cwes} CWE · ${stats.cves} CVE · ${stats.mappedCapecs} CAPEC mapeados a STRIDE`;
    renderStrideCards();
    renderResults();
    renderDetail();
}

function openItem(kind, id) {
    if (kind === "stride") {
        state.stride = state.stride === id ? null : id;
        state.selected = state.stride ? { kind: "stride", id } : null;
        state.tab = "related";
        setHash("stride", state.stride || id);
        if (!state.stride) history.replaceState(null, "", location.pathname);
        render();
        return;
    }
    state.selected = { kind, id };
    state.tab = "related";
    const related = relatedFor(kind, id);
    if (state.stride && related && !(related.stride || []).includes(state.stride)) {
        state.stride = null;
    }
    setHash(kind, id);
    render();
}

function bindEvents() {
    els.searchInput.addEventListener("input", (event) => {
        state.query = event.target.value;
        renderResults();
    });
    els.typeFilter.addEventListener("change", (event) => {
        state.type = event.target.value;
        renderResults();
    });
    els.strideGrid.addEventListener("click", (event) => {
        const button = event.target.closest("[data-stride]");
        if (button) openItem("stride", button.dataset.stride);
    });
    els.results.addEventListener("click", (event) => {
        const button = event.target.closest("[data-kind]");
        if (button) openItem(button.dataset.kind, button.dataset.id);
    });
    els.detailPane.addEventListener("click", (event) => {
        const tab = event.target.closest("[data-tab]");
        if (tab) {
            state.tab = tab.dataset.tab;
            renderDetail();
            return;
        }
        const chip = event.target.closest("[data-open]");
        if (!chip) return;
        const parsed = parseOpenToken(chip.dataset.open);
        if (parsed) openItem(parsed.kind, parsed.id);
    });
    window.addEventListener("hashchange", () => {
        selectFromHash();
        render();
    });
}

async function boot() {
    try {
        const [graphRes, catalogRes] = await Promise.all([fetch(GRAPH_URL), fetch(CATALOG_URL)]);
        if (!graphRes.ok) throw new Error("Falha ao carregar o grafo correlacionado");
        state.graph = await graphRes.json();
        state.catalog = catalogRes.ok ? await catalogRes.json() : { categories: [] };
        selectFromHash();
        if (!state.selected) {
            state.stride = "R";
            state.selected = { kind: "stride", id: "R" };
            if (!location.hash) setHash("stride", "R");
        }
        bindEvents();
        render();
    } catch (error) {
        els.statsLine.textContent = "Erro ao carregar dados. Rode python3 tools/build_graph.py e sirva a pasta do projeto.";
        console.error(error);
    }
}

boot();
