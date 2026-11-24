/* ==========================================================================
   LensGuard — Interactive Pipeline Visualizer
   n8n / ReactFlow-style live processing graph
   ========================================================================== */
(function () {
  "use strict";

  /* ---- Pipeline Node Definitions ---- */
  const NODES = [
    { id: "input",      label: "Input",         icon: "i-upload",     col: 0, row: 1,   desc: "Document or text received for analysis" },
    { id: "extract",    label: "Extract",        icon: "i-file",       col: 1, row: 1,   desc: "Text extraction from PDF/DOCX/TXT/MD" },
    { id: "chunk",      label: "Chunking",       icon: "i-code",       col: 2, row: 1,   desc: "Split text into segments for per-chunk analysis" },
    { id: "rules",      label: "L1 Rules",       icon: "i-shield",     col: 3, row: 0,   desc: "Weighted regex patterns & lexical signals" },
    { id: "structural", label: "L2 Structural",  icon: "i-search",     col: 3, row: 1,   desc: "Hidden text, metadata, annotations, zero-width chars" },
    { id: "decode",     label: "L2.5 Decode",    icon: "i-command",    col: 3, row: 2,   desc: "Base64 / hex / URL-encoded / HTML entity unpacking" },
    { id: "ml",         label: "ML Classifier",  icon: "i-activity",   col: 4, row: 0.5, desc: "TF-IDF + Logistic Regression injection classifier" },
    { id: "judge",      label: "AI Judge",       icon: "i-plug",       col: 4, row: 2,   desc: "LLM semantic judge (Gemini / Ollama Cloud)" },
    { id: "fusion",     label: "Score Fusion",   icon: "i-chart",      col: 5, row: 1,   desc: "Combine rule, ML and judge scores into final risk" },
    { id: "verdict",    label: "Verdict",        icon: "i-alert",      col: 6, row: 0.5, desc: "Final document risk classification" },
    { id: "sanitise",   label: "Sanitise",       icon: "i-check",      col: 6, row: 1.5, desc: "Strip malicious content and wrap in security envelope" },
  ];

  const EDGES = [
    ["input",      "extract"],
    ["extract",    "chunk"],
    ["chunk",      "rules"],
    ["chunk",      "structural"],
    ["chunk",      "decode"],
    ["rules",      "ml"],
    ["structural", "ml"],
    ["decode",     "judge"],
    ["ml",         "fusion"],
    ["rules",      "fusion"],
    ["structural", "fusion"],
    ["judge",      "fusion"],
    ["fusion",     "verdict"],
    ["fusion",     "sanitise"],
  ];

  /* ---- Layout constants ---- */
  const NODE_W = 130;
  const NODE_H = 56;
  const COL_GAP = 140;
  const ROW_GAP = 100;
  const PADDING_X = 30;
  const PADDING_Y = 40;

  function nodePos(node) {
    return {
      x: PADDING_X + node.col * COL_GAP,
      y: PADDING_Y + node.row * ROW_GAP,
    };
  }

  /* ---- Render ---- */
  let container = null;
  let svgEl = null;
  let detailEl = null;
  let selectedNode = null;
  let nodeEls = {};
  let nodeStates = {};   // id → { state, data }
  let scanData = null;

  function init() {
    container = document.getElementById("pipelineGraph");
    if (!container) return;

    // Build SVG edge layer
    svgEl = document.createElementNS("http://www.w3.org/2000/svg", "svg");
    svgEl.classList.add("pipeline-edges");
    svgEl.setAttribute("xmlns", "http://www.w3.org/2000/svg");
    container.appendChild(svgEl);

    // Build nodes
    NODES.forEach(function (n) {
      var pos = nodePos(n);
      var div = document.createElement("div");
      div.className = "pipeline-node is-idle";
      div.dataset.nodeId = n.id;
      div.style.left = pos.x + "px";
      div.style.top = pos.y + "px";

      div.innerHTML =
        '<div class="pn-body">' +
          '<span class="pn-status-dot"></span>' +
          '<span class="pn-icon"><svg aria-hidden="true"><use href="#' + n.icon + '"></use></svg></span>' +
          '<span class="pn-label">' + n.label + '</span>' +
        '</div>' +
        '<span class="pn-badge" id="pnBadge-' + n.id + '">—</span>';

      div.addEventListener("click", function (e) {
        e.stopPropagation();
        toggleDetail(n);
      });

      container.appendChild(div);
      nodeEls[n.id] = div;
      nodeStates[n.id] = { state: "idle", data: null };
    });

    // Draw edges
    drawEdges();

    // Build detail popover
    detailEl = document.createElement("div");
    detailEl.className = "pipeline-detail";
    detailEl.id = "pipelineDetail";
    container.appendChild(detailEl);

    // Close on outside click
    document.addEventListener("click", function () {
      closeDetail();
    });

    // Set graph size
    var maxX = 0, maxY = 0;
    NODES.forEach(function (n) {
      var p = nodePos(n);
      maxX = Math.max(maxX, p.x + NODE_W + 60);
      maxY = Math.max(maxY, p.y + NODE_H + 70);
    });
    container.style.minWidth = maxX + "px";
    container.style.minHeight = maxY + "px";
    svgEl.setAttribute("viewBox", "0 0 " + maxX + " " + maxY);
    svgEl.style.width = maxX + "px";
    svgEl.style.height = maxY + "px";
  }

  function drawEdges() {
    if (!svgEl) return;
    svgEl.innerHTML = "";

    EDGES.forEach(function (e) {
      var fromN = NODES.find(function (n) { return n.id === e[0]; });
      var toN = NODES.find(function (n) { return n.id === e[1]; });
      if (!fromN || !toN) return;

      var from = nodePos(fromN);
      var to = nodePos(toN);

      var x1 = from.x + NODE_W;
      var y1 = from.y + NODE_H / 2;
      var x2 = to.x;
      var y2 = to.y + NODE_H / 2;

      var cpx1 = x1 + (x2 - x1) * 0.4;
      var cpx2 = x2 - (x2 - x1) * 0.4;

      var d = "M " + x1 + " " + y1 + " C " + cpx1 + " " + y1 + " " + cpx2 + " " + y2 + " " + x2 + " " + y2;

      // Static edge
      var path = document.createElementNS("http://www.w3.org/2000/svg", "path");
      path.setAttribute("d", d);
      path.classList.add("pipeline-edge");
      path.dataset.from = e[0];
      path.dataset.to = e[1];
      svgEl.appendChild(path);

      // Flow overlay
      var flow = document.createElementNS("http://www.w3.org/2000/svg", "path");
      flow.setAttribute("d", d);
      flow.classList.add("pipeline-edge-flow");
      flow.dataset.from = e[0];
      flow.dataset.to = e[1];
      svgEl.appendChild(flow);
    });
  }

  /* ---- State updates ---- */
  function setNodeState(id, state, badgeText, data) {
    var el = nodeEls[id];
    if (!el) return;

    el.classList.remove("is-idle", "is-processing", "is-done", "is-flagged", "is-skipped");
    el.classList.add("is-" + state);

    nodeStates[id] = { state: state, data: data || null };

    var badge = el.querySelector(".pn-badge");
    if (badge && badgeText !== undefined) {
      badge.textContent = badgeText;
    }

    // Update edges leading to this node
    updateEdgeState(id, state);
  }

  function updateEdgeState(toId, state) {
    if (!svgEl) return;
    var edges = svgEl.querySelectorAll('.pipeline-edge[data-to="' + toId + '"]');
    var flows = svgEl.querySelectorAll('.pipeline-edge-flow[data-to="' + toId + '"]');

    edges.forEach(function (e) {
      e.classList.remove("is-active", "is-danger");
      if (state === "processing") e.classList.add("is-active");
      else if (state === "done" || state === "flagged") e.classList.add("is-active");
    });

    flows.forEach(function (f) {
      f.classList.remove("is-flowing");
      if (state === "processing") f.classList.add("is-flowing");
    });
  }

  function resetAll() {
    NODES.forEach(function (n) {
      setNodeState(n.id, "idle", "—", null);
    });
    scanData = null;
    closeDetail();
  }

  /* ---- Live scan animation ---- */
  // Called by the scan flow after results arrive
  function animateScan(result) {
    scanData = result;
    resetAll();

    var chunks = result.chunks || [];
    var layers = result.layers || {};
    var n_chunks = result.n_chunks || chunks.length;
    var n_flagged = result.n_flagged || 0;
    var hasJudge = chunks.some(function (c) { return c.judge && c.judge.verdict !== "error"; });
    var hasDecoded = chunks.some(function (c) { return c.decoded; });
    var hasMl = chunks.some(function (c) { return c.ml_prob > 0; });
    var hasStructural = layers.structural;

    // Gather per-layer stats
    var ruleHits = 0, mlHits = 0, structHits = 0, decodeHits = 0, judgeHits = 0;
    var ruleCats = {};
    chunks.forEach(function (c) {
      (c.matched || []).forEach(function (m) {
        if (m.category === "ml_classifier") mlHits++;
        else {
          ruleHits++;
          ruleCats[m.category] = (ruleCats[m.category] || 0) + 1;
        }
      });
      if (c.decoded) decodeHits++;
      if (c.structural > 0) structHits++;
      if (c.judge && c.judge.verdict !== "error") judgeHits++;
    });

    // Stagger animation
    var delay = 0;
    var step = 220;

    // 1. Input
    setTimeout(function () { setNodeState("input", "processing", "Received", { type: "input", source: result.source_name }); }, delay);
    delay += step;
    setTimeout(function () { setNodeState("input", "done", result.source_name || "File", { type: "input", source: result.source_name }); }, delay);

    // 2. Extract
    delay += step;
    setTimeout(function () { setNodeState("extract", "processing", "Parsing…"); }, delay);
    delay += step * 1.5;
    setTimeout(function () {
      setNodeState("extract", "done", n_chunks + " segments", {
        type: "extract",
        format: (result.source_name || "").split(".").pop().toUpperCase() || "TXT",
        segments: n_chunks,
      });
    }, delay);

    // 3. Chunk
    delay += step;
    setTimeout(function () { setNodeState("chunk", "processing", "Splitting…"); }, delay);
    delay += step;
    setTimeout(function () {
      setNodeState("chunk", "done", n_chunks + " chunks", {
        type: "chunk",
        count: n_chunks,
      });
    }, delay);

    // 4. Parallel layers
    var parallelDelay = delay + step;

    // Rules
    setTimeout(function () { setNodeState("rules", "processing", "Scanning…"); }, parallelDelay);
    setTimeout(function () {
      var st = ruleHits > 0 ? "flagged" : "done";
      setNodeState("rules", st, ruleHits + " hits", {
        type: "rules",
        hits: ruleHits,
        categories: ruleCats,
        findings: chunks.flatMap(function (c) {
          return (c.matched || []).filter(function (m) { return m.category !== "ml_classifier"; });
        }).slice(0, 10),
      });
    }, parallelDelay + step * 2);

    // Structural
    setTimeout(function () { setNodeState("structural", "processing", "Inspecting…"); }, parallelDelay + step * 0.3);
    setTimeout(function () {
      var st2 = structHits > 0 ? "flagged" : "done";
      setNodeState("structural", st2, structHits > 0 ? structHits + " anomalies" : "Clean", {
        type: "structural",
        hits: structHits,
        active: hasStructural,
      });
    }, parallelDelay + step * 2.3);

    // Decode
    setTimeout(function () { setNodeState("decode", "processing", "Unpacking…"); }, parallelDelay + step * 0.6);
    setTimeout(function () {
      if (!hasDecoded && decodeHits === 0) {
        setNodeState("decode", "skipped", "No encoded", {
          type: "decode",
          hits: 0,
          skipped: true,
        });
      } else {
        var st3 = decodeHits > 0 ? "flagged" : "done";
        setNodeState("decode", st3, decodeHits + " decoded", {
          type: "decode",
          hits: decodeHits,
        });
      }
    }, parallelDelay + step * 2.6);

    // 5. ML Classifier
    var mlDelay = parallelDelay + step * 3;
    setTimeout(function () {
      if (hasMl) {
        setNodeState("ml", "processing", "Classifying…");
      } else {
        setNodeState("ml", "skipped", "Inactive", { type: "ml", active: false });
      }
    }, mlDelay);
    setTimeout(function () {
      if (hasMl) {
        var st4 = mlHits > 0 ? "flagged" : "done";
        var maxProb = Math.max.apply(null, chunks.map(function (c) { return c.ml_prob || 0; }));
        setNodeState("ml", st4, (maxProb * 100).toFixed(0) + "% peak", {
          type: "ml",
          active: true,
          hits: mlHits,
          maxProb: maxProb,
          threshold: result.layers && result.layers.ml_classifier ? result.layers.ml_classifier : "0.72",
          chunkScores: chunks.map(function (c) { return { prob: c.ml_prob, score: c.ml_score }; }),
        });
      }
    }, mlDelay + step * 1.5);

    // AI Judge
    var judgeDelay = mlDelay + step * 0.5;
    setTimeout(function () {
      if (hasJudge) {
        setNodeState("judge", "processing", "Judging…");
      } else {
        setNodeState("judge", "skipped", "Skipped", {
          type: "judge",
          reason: layers.llm_judge || "No borderline chunks",
          active: false,
        });
      }
    }, judgeDelay);
    setTimeout(function () {
      if (hasJudge) {
        var injections = chunks.filter(function (c) {
          return c.judge && c.judge.verdict === "injection";
        }).length;
        var st5 = injections > 0 ? "flagged" : "done";
        setNodeState("judge", st5, judgeHits + " judged", {
          type: "judge",
          active: true,
          calls: result.judge_calls,
          cached: result.cache_hits,
          engine: result.judge_label,
          injections: injections,
          verdicts: chunks.filter(function (c) { return c.judge; }).map(function (c) {
            return { verdict: c.judge.verdict, confidence: c.judge.confidence, reason: c.judge.reason };
          }).slice(0, 6),
        });
      }
    }, judgeDelay + step * 2);

    // 6. Score Fusion
    var fusionDelay = mlDelay + step * 3;
    setTimeout(function () { setNodeState("fusion", "processing", "Fusing…"); }, fusionDelay);
    setTimeout(function () {
      setNodeState("fusion", n_flagged > 0 ? "flagged" : "done",
        "Score: " + result.doc_score, {
          type: "fusion",
          doc_score: result.doc_score,
          n_flagged: n_flagged,
          n_chunks: n_chunks,
        });
    }, fusionDelay + step * 1.5);

    // 7. Verdict
    var verdictDelay = fusionDelay + step * 2;
    setTimeout(function () { setNodeState("verdict", "processing", "Deciding…"); }, verdictDelay);
    setTimeout(function () {
      var vState = result.verdict === "CLEAN" || result.verdict === "LOW" ? "done" : "flagged";
      setNodeState("verdict", vState, result.verdict, {
        type: "verdict",
        verdict: result.verdict,
        score: result.doc_score,
      });
    }, verdictDelay + step);

    // 8. Sanitise
    var sanDelay = verdictDelay + step * 0.5;
    setTimeout(function () { setNodeState("sanitise", "processing", "Cleaning…"); }, sanDelay);
    setTimeout(function () {
      var san = result.sanitisation || {};
      var removed = (san.removed_items || []).length;
      var sState = removed > 0 ? "flagged" : "done";
      setNodeState("sanitise", sState, removed > 0 ? removed + " removed" : "Clean", {
        type: "sanitise",
        removed: removed,
        modified: san.is_modified,
        items: (san.removed_items || []).slice(0, 8),
      });
    }, sanDelay + step * 1.5);
  }

  /* ---- Detail popover ---- */
  function toggleDetail(nodeDef) {
    if (selectedNode === nodeDef.id) {
      closeDetail();
      return;
    }
    selectedNode = nodeDef.id;

    // Highlight selected
    Object.values(nodeEls).forEach(function (el) { el.classList.remove("is-selected"); });
    if (nodeEls[nodeDef.id]) nodeEls[nodeDef.id].classList.add("is-selected");

    var state = nodeStates[nodeDef.id] || {};
    var data = state.data || {};
    var pos = nodePos(nodeDef);

    var html = '<div class="pipeline-detail-header">';
    html += '<span class="pipeline-detail-icon" style="background:var(--surface-inset);color:var(--text-secondary);">';
    html += '<svg aria-hidden="true"><use href="#' + nodeDef.icon + '"></use></svg></span>';
    html += '<div><div class="pipeline-detail-title">' + nodeDef.label + '</div>';
    html += '<div class="pipeline-detail-status">' + (state.state || "idle") + '</div></div>';
    html += '<button class="pipeline-detail-close" onclick="window.PIDPipeline.closeDetail()"><svg aria-hidden="true"><use href="#i-x"></use></svg></button>';
    html += '</div>';

    html += '<div style="font-size:12px;color:var(--text-secondary);margin-bottom:12px;">' + nodeDef.desc + '</div>';

    // Type-specific detail content
    if (data.type === "input") {
      html += pdRow("Source", data.source || "—");
    } else if (data.type === "extract") {
      html += pdRow("Format", data.format || "—");
      html += pdRow("Segments", data.segments);
    } else if (data.type === "chunk") {
      html += pdRow("Total Chunks", data.count);
    } else if (data.type === "rules") {
      html += pdRow("Pattern Hits", data.hits);
      if (data.categories && Object.keys(data.categories).length > 0) {
        html += '<div style="font-size:11px;font-weight:600;margin-top:8px;color:var(--text-muted);">Category Breakdown</div>';
        Object.keys(data.categories).forEach(function (cat) {
          html += pdRow(cat, data.categories[cat] + " hit(s)");
        });
      }
      if (data.findings && data.findings.length > 0) {
        html += '<div class="pd-findings">';
        data.findings.forEach(function (f) {
          html += '<div class="pd-finding-item">';
          html += '<div class="pd-finding-cat">' + escapeHtml(f.category || "rule") + '</div>';
          html += '<div class="pd-finding-snippet">' + escapeHtml((f.snippet || "").substring(0, 120)) + '</div>';
          html += '</div>';
        });
        html += '</div>';
      }
    } else if (data.type === "structural") {
      html += pdRow("Anomalies Found", data.hits);
      html += pdRow("Active", data.active ? "Yes" : "No");
    } else if (data.type === "decode") {
      html += pdRow("Decoded Chunks", data.hits);
      if (data.skipped) html += pdRow("Status", "No encoded content found");
    } else if (data.type === "ml") {
      html += pdRow("Active", data.active ? "Yes" : "No");
      if (data.active) {
        html += pdRow("ML Flagged", data.hits + " chunk(s)");
        html += pdRow("Peak Probability", (data.maxProb * 100).toFixed(1) + "%");
        html += pdRow("Threshold", data.threshold);
      }
    } else if (data.type === "judge") {
      html += pdRow("Active", data.active ? "Yes" : "No");
      if (data.active) {
        html += pdRow("Judge Calls", data.calls);
        html += pdRow("Cached", data.cached);
        html += pdRow("Engine", data.engine || "—");
        html += pdRow("Injections Found", data.injections);
        if (data.verdicts && data.verdicts.length > 0) {
          html += '<div class="pd-findings">';
          data.verdicts.forEach(function (v) {
            html += '<div class="pd-finding-item">';
            html += '<div class="pd-finding-cat">' + escapeHtml(v.verdict) + ' (' + (v.confidence || 0) + ')</div>';
            html += '<div class="pd-finding-snippet">' + escapeHtml((v.reason || "").substring(0, 100)) + '</div>';
            html += '</div>';
          });
          html += '</div>';
        }
      } else {
        html += pdRow("Reason", data.reason || "—");
      }
    } else if (data.type === "fusion") {
      html += pdRow("Document Score", data.doc_score + " / 100");
      html += pdRow("Flagged Chunks", data.n_flagged + " of " + data.n_chunks);
    } else if (data.type === "verdict") {
      html += pdRow("Final Verdict", data.verdict);
      html += pdRow("Risk Score", data.score + " / 100");
    } else if (data.type === "sanitise") {
      html += pdRow("Items Removed", data.removed);
      html += pdRow("Content Modified", data.modified ? "Yes" : "No");
      if (data.items && data.items.length > 0) {
        html += '<div class="pd-findings">';
        data.items.forEach(function (item) {
          html += '<div class="pd-finding-item">';
          html += '<div class="pd-finding-cat">' + escapeHtml(item.type || item.category || "rule") + '</div>';
          html += '<div class="pd-finding-snippet">' + escapeHtml((item.snippet || item.reason || "").substring(0, 100)) + '</div>';
          html += '</div>';
        });
        html += '</div>';
      }
    }

    detailEl.innerHTML = html;

    // Position below the node
    detailEl.style.left = Math.max(0, pos.x - 90) + "px";
    detailEl.style.top = (pos.y + NODE_H + 20) + "px";
    detailEl.classList.add("is-visible");
  }

  function closeDetail() {
    if (detailEl) detailEl.classList.remove("is-visible");
    selectedNode = null;
    Object.values(nodeEls).forEach(function (el) { el.classList.remove("is-selected"); });
  }

  function pdRow(label, value) {
    return '<div class="pd-row"><span class="pd-label">' + label + '</span><span class="pd-value">' + (value !== undefined ? value : "—") + '</span></div>';
  }

  function escapeHtml(str) {
    var div = document.createElement("div");
    div.appendChild(document.createTextNode(str || ""));
    return div.innerHTML;
  }

  /* ---- Public API ---- */
  window.PIDPipeline = {
    init: init,
    animateScan: animateScan,
    resetAll: resetAll,
    closeDetail: closeDetail,
  };
})();
