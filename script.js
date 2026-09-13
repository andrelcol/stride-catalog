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
    state.tab = parsed.kind === "stride" ? "related" : "why";
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

const SCOPE_WHY = {
    Confidentiality: { stride: "I", text: "Confidencialidade — dados visíveis para quem não deveria vê-los." },
    Integrity: { stride: "T", text: "Integridade — dados, código ou estado são alterados." },
    Availability: { stride: "D", text: "Disponibilidade — o sistema deixa de atender o uso legítimo." },
    "Access Control": { stride: "E", text: "Controle de acesso — o atacante passa a fazer o que a política deveria barrar." },
    Authorization: { stride: "E", text: "Autorização — privilégio ou comando além do permitido." },
    Authentication: { stride: "S", text: "Autenticação — a identidade não é verificada de fato." },
    "Non-Repudiation": { stride: "R", text: "Não-repúdio — fica possível negar autoria de uma ação." },
    Accountability: { stride: "R", text: "Accountability — some a trilha de quem fez o quê (esconder atividades, forjar origem)." },
    Identity: { stride: "S", text: "Identidade — o atacante assume ou forja quem é o ator." },
};

function mappingSource() {
    const source = state.graph?.meta?.sources || {};
    return source.url || "https://medium.com/@brettcrawley/capec-stride-mapping-1aa83a058c5d";
}

function capecNode(id) {
    return state.graph.capecs[id];
}

function cweNode(id) {
    return state.graph.cwes[id];
}

function cveNode(id) {
    return state.graph.cves[id];
}

function consequencesForStride(node, letter) {
    return (node?.consequences || []).filter((row) =>
        (row.scopes || []).some((scope) => SCOPE_WHY[scope]?.stride === letter)
    );
}

function formatConsequences(rows) {
    return rows
        .map((row) => {
            const scopes = (row.scopes || []).join(", ");
            const impacts = (row.impacts || []).join(", ");
            const note = row.note ? ` — ${row.note}` : "";
            return `${scopes}${impacts ? ` / ${impacts}` : ""}${note}`;
        })
        .join("; ");
}

function whyStrideForCapec(capec, letter) {
    const name = strideName(letter);
    const parts = [];
    if ((capec.strideMapped || []).includes(letter)) {
        parts.push(
            `Brett Crawley classificou este padrão no mapa CAPEC–STRIDE como <strong>${escapeHtml(name)}</strong>.`
        );
    }
    const inferredRows = consequencesForStride(capec, letter);
    if ((capec.strideInferred || []).includes(letter) || inferredRows.length) {
        const detail = formatConsequences(inferredRows) || (capec.scopes || []).join(", ");
        parts.push(
            `O MITRE CAPEC declara consequências ${escapeHtml(detail)}, e esse escopo corresponde a <strong>${escapeHtml(name)}</strong>.`
        );
    }
    if (!parts.length && (capec.stride || []).includes(letter)) {
        parts.push(`Este padrão está associado a <strong>${escapeHtml(name)}</strong> no grafo correlacionado.`);
    }
    return parts;
}

function whyStrideForCwe(cwe, letter) {
    const name = strideName(letter);
    const parts = [];
    if ((cwe.strideFromCapec || []).includes(letter)) {
        const capecs = (cwe.capecs || [])
            .filter((id) => (capecNode(id)?.stride || []).includes(letter))
            .slice(0, 8)
            .map((id) => `CAPEC-${id}`);
        parts.push(
            `Herdado dos padrões de ataque relacionados (${escapeHtml(capecs.join(", ") || "CAPEC")}), já classificados como <strong>${escapeHtml(name)}</strong>.`
        );
    }
    const inferredRows = consequencesForStride(cwe, letter);
    if ((cwe.strideFromConsequences || []).includes(letter) || inferredRows.length) {
        const detail = formatConsequences(inferredRows) || (cwe.scopes || []).join(", ");
        parts.push(
            `As Common Consequences do CWE incluem ${escapeHtml(detail)}, o que mapeia para <strong>${escapeHtml(name)}</strong>.`
        );
    }
    return parts;
}

function whyCapecCwe(capecId, cweId) {
    const capec = capecNode(capecId);
    const cwe = cweNode(cweId);
    if (!capec || !cwe) return [];
    const reasons = new Set([
        ...((capec.cweWhy && capec.cweWhy[cweId]) || []),
        ...((cwe.capecWhy && cwe.capecWhy[capecId]) || []),
    ]);
    const parts = [];
    if (reasons.has("capec_related_weakness")) {
        parts.push(
            `O MITRE CAPEC lista <strong>CWE-${escapeHtml(cweId)}</strong> em <em>Related Weaknesses</em>: é a fraqueza que o ataque explora.`
        );
    }
    if (reasons.has("cwe_related_attack_pattern")) {
        parts.push(
            `O MITRE CWE lista <strong>CAPEC-${escapeHtml(capecId)}</strong> em <em>Related Attack Patterns</em>: este é um modo conhecido de explorar a fraqueza.`
        );
    }
    parts.push(
        `<strong>CAPEC-${escapeHtml(capecId)} (${escapeHtml(capec.name)})</strong> usa a condição descrita por <strong>CWE-${escapeHtml(cweId)} (${escapeHtml(cwe.name)})</strong>: ${escapeHtml(cwe.summary)}`
    );
    return parts;
}

function whyCweCve(cweId, cveId) {
    const cwe = cweNode(cweId);
    const cve = cveNode(cveId);
    if (!cwe || !cve) return [];
    const source = (cwe.cveWhy && cwe.cveWhy[cveId]) || (cve.cweWhy && cve.cweWhy[cweId]) || cve.source || "";
    const parts = [];
    if (String(source).includes("cwe_observed_example")) {
        parts.push(
            `O MITRE CWE cita <strong>${escapeHtml(cveId)}</strong> como exemplo observado de <strong>CWE-${escapeHtml(cweId)}</strong>.`
        );
    }
    if (String(source).includes("cve_problem_type") || String(source).includes("local_cve_json")) {
        parts.push(
            `O registro CVE declara <strong>CWE-${escapeHtml(cweId)}</strong> em <em>problemTypes</em>.`
        );
    }
    if (cve.summary || cve.title) {
        parts.push(escapeHtml(cve.summary || cve.title));
    }
    return parts;
}

function whyBlock(title, openToken, paragraphs) {
    if (!paragraphs.length) return "";
    const heading = openToken
        ? `<button class="chip" data-open="${escapeHtml(openToken)}">${escapeHtml(title)}</button>`
        : `<h3>${escapeHtml(title)}</h3>`;
    return `
        <article class="why">
            ${heading}
            ${paragraphs.map((text) => `<p>${text}</p>`).join("")}
        </article>`;
}

function whyView(related) {
    const kind = state.selected.kind;
    const id = state.selected.id;
    const blocks = [];

    if (kind === "stride") {
        const meta = state.graph.stride.find((item) => item.id === id);
        const mappedIds = [];
        const inferredIds = [];
        for (const capecId of related.capecs) {
            const capec = capecNode(capecId);
            if (!capec) continue;
            if ((capec.strideMapped || []).includes(id)) mappedIds.push(capecId);
            else inferredIds.push(capecId);
        }
        blocks.push(
            whyBlock(
                `${id} · ${meta?.name || ""}`,
                null,
                [
                    escapeHtml(meta?.description || ""),
                    `Os CAPEC desta categoria vêm de duas origens: o mapa de <a href="${escapeHtml(mappingSource())}" target="_blank" rel="noopener">Brett Crawley</a> (${mappedIds.length} padrões) e a inferência pelas consequências MITRE (${inferredIds.length} padrões, por exemplo Accountability → Repudiation).`,
                    `CWE e CVE aparecem porque o MITRE liga CAPEC↔CWE (<em>Related Weaknesses</em> / <em>Related Attack Patterns</em>) e CWE↔CVE (exemplos observados ou problemTypes do CVE).`,
                ]
            )
        );
        if (mappedIds.length) {
            blocks.push(
                whyBlock(
                    "No mapa Brett Crawley",
                    null,
                    [`${mappedIds.map((capecId) => `<button class="chip" data-open="CAPEC-${capecId}">CAPEC-${capecId}</button>`).join(" ")}`]
                )
            );
        }
        for (const capecId of inferredIds.slice(0, 12)) {
            const capec = capecNode(capecId);
            blocks.push(whyBlock(`CAPEC-${capecId} · ${capec?.name || ""}`, `CAPEC-${capecId}`, whyStrideForCapec(capec, id)));
        }
        if (inferredIds.length > 12) {
            blocks.push(`<p class="meta">Mostrando 12 de ${inferredIds.length} CAPECs inferidos. Abra um CAPEC para o detalhe completo.</p>`);
        }
        return blocks.join("");
    }

    if (kind === "capec") {
        const capec = related.node;
        for (const letter of capec.stride || []) {
            blocks.push(whyBlock(strideName(letter), `STRIDE-${letter}`, whyStrideForCapec(capec, letter)));
        }
        if (capec.parents?.length) {
            blocks.push(
                whyBlock(
                    `Especialização de ${capec.parents.map((parent) => "CAPEC-" + parent).join(", ")}`,
                    `CAPEC-${capec.parents[0]}`,
                    [`MITRE marca este padrão como filho (ChildOf) de ${escapeHtml(capec.parents.map((parent) => `CAPEC-${parent} (${capecNode(parent)?.name || ""})`).join(", "))}.`]
                )
            );
        }
        for (const cweId of (capec.cwes || []).slice(0, 12)) {
            blocks.push(whyBlock(`CWE-${cweId} · ${cweNode(cweId)?.name || ""}`, `CWE-${cweId}`, whyCapecCwe(id, cweId)));
        }
        return blocks.join("") || `<p class="meta">Não há texto de origem para este recorte.</p>`;
    }

    if (kind === "cwe") {
        const cwe = related.node;
        for (const letter of cwe.stride || []) {
            blocks.push(whyBlock(strideName(letter), `STRIDE-${letter}`, whyStrideForCwe(cwe, letter)));
        }
        for (const capecId of (cwe.capecs || []).slice(0, 12)) {
            blocks.push(whyBlock(`CAPEC-${capecId} · ${capecNode(capecId)?.name || ""}`, `CAPEC-${capecId}`, whyCapecCwe(capecId, id)));
        }
        for (const cveId of (cwe.cves || []).slice(0, 8)) {
            blocks.push(whyBlock(cveId, cveId, whyCweCve(id, cveId)));
        }
        return blocks.join("") || `<p class="meta">Não há texto de origem para este recorte.</p>`;
    }

    const cve = related.node;
    for (const letter of cve.stride || []) {
        blocks.push(
            whyBlock(
                strideName(letter),
                `STRIDE-${letter}`,
                [`O CVE herda STRIDE dos CWE que declara: ${(cve.cwes || []).map((cweId) => "CWE-" + cweId).join(", ") || "nenhum CWE"}.`]
            )
        );
    }
    for (const cweId of (cve.cwes || []).slice(0, 12)) {
        blocks.push(whyBlock(`CWE-${cweId} · ${cweNode(cweId)?.name || ""}`, `CWE-${cweId}`, whyCweCve(cweId, id)));
    }
    return blocks.join("") || `<p class="meta">Não há texto de origem para este recorte.</p>`;
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
            <button data-tab="why" class="${state.tab === "why" ? "active" : ""}">Por que se relacionam</button>
            <button data-tab="code" class="${state.tab === "code" ? "active" : ""}">Como achar no código</button>
        </div>
        ${state.tab === "code" && heuristics[0] ? `<p><strong>${escapeHtml(heuristics[0].codeQuestion)}</strong></p><p class="meta">${escapeHtml(state.catalog.intro)}</p>` : ""}
        ${state.tab === "related" ? relatedView : state.tab === "why" ? whyView(related) : codeView}
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
    state.tab = "why";
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
