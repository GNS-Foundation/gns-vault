/**
 * GNS Vault — AIP Agent Detector (Content Script Module)
 *
 * Detects AI agent declarations on the current page via:
 *   A) <meta name="gns-aip-agent"> tags
 *   B) window.__GNS_AIP_AGENTS__ global (SPA frameworks)
 *   C) <script data-gns-aip> attributes
 *   D) GNS Auth SDK agent declarations (gns-aip-agent-declared event)
 *
 * Complements the background's /.well-known/gns-aip.json fetch and
 * _gns-aip DNS TXT fallback — this module catches agents that only
 * declare themselves client-side (common in SPA architectures).
 *
 * Detected agents are forwarded to the background via
 * AIP_AGENTS_DETECTED message for provenance verification.
 *
 * @module vault-extension/content/aip-detector
 */

// ============================================================
// TYPES
// ============================================================

interface DetectedAgent {
    agent_key: string;
    model_id?: string;
    creator_org?: string;
    deployer_org?: string;
    capabilities?: string[];
    source: 'meta' | 'global' | 'script' | 'sdk';
}

// ============================================================
// STATE
// ============================================================

/** Track detected agents to avoid duplicate messages */
const detectedKeys = new Set<string>();

/** Whether initial scan has completed */
let initialScanDone = false;

// ============================================================
// DETECTION METHODS
// ============================================================

/**
 * Scan <meta name="gns-aip-agent"> tags.
 *
 * Expected format:
 *   <meta name="gns-aip-agent"
 *         content="key=<hex64>; model=claude-sonnet; creator=anthropic.com">
 *
 * Multiple meta tags = multiple agents.
 */
function scanMetaTags(): DetectedAgent[] {
    const agents: DetectedAgent[] = [];
    const metas = document.querySelectorAll<HTMLMetaElement>('meta[name="gns-aip-agent"]');

    for (const meta of metas) {
        const content = meta.content?.trim();
        if (!content) continue;

        const pairs: Record<string, string> = {};
        content.split(';').forEach(part => {
            const eq = part.indexOf('=');
            if (eq > 0) pairs[part.substring(0, eq).trim().toLowerCase()] = part.substring(eq + 1).trim();
        });

        if (!pairs.key || !/^[0-9a-fA-F]{64}$/.test(pairs.key)) continue;

        agents.push({
            agent_key: pairs.key.toLowerCase(),
            model_id: pairs.model || pairs.model_id,
            creator_org: pairs.creator || pairs.creator_org,
            deployer_org: pairs.deployer || pairs.deployer_org,
            capabilities: pairs.capabilities?.split(',').map(s => s.trim()),
            source: 'meta',
        });
    }

    return agents;
}

/**
 * Check window.__GNS_AIP_AGENTS__ global.
 *
 * SPA frameworks (Next.js, Nuxt, etc.) may set this global
 * in their runtime to declare agents without meta tags.
 *
 * Expected format:
 *   window.__GNS_AIP_AGENTS__ = [
 *     { agent_key: '<hex64>', model_id: '...', creator_org: '...' }
 *   ]
 *
 * We read it via a script injection to access the page's JS context
 * (content scripts run in an isolated world).
 */
function scanGlobalVariable(): Promise<DetectedAgent[]> {
    return new Promise((resolve) => {
        // Inject a script that reads the global and posts it back
        const script = document.createElement('script');
        script.textContent = `
      (function() {
        if (window.__GNS_AIP_AGENTS__ && Array.isArray(window.__GNS_AIP_AGENTS__)) {
          window.postMessage({
            type: '__GNS_AIP_GLOBAL_RESULT__',
            agents: window.__GNS_AIP_AGENTS__
          }, '*');
        } else {
          window.postMessage({ type: '__GNS_AIP_GLOBAL_RESULT__', agents: [] }, '*');
        }
      })();
    `;

        const timeout = setTimeout(() => {
            cleanup();
            resolve([]);
        }, 500);

        const handler = (event: MessageEvent) => {
            if (event.source !== window) return;
            if (event.data?.type !== '__GNS_AIP_GLOBAL_RESULT__') return;
            cleanup();
            resolve(parseGlobalAgents(event.data.agents));
        };

        const cleanup = () => {
            clearTimeout(timeout);
            window.removeEventListener('message', handler);
            script.remove();
        };

        window.addEventListener('message', handler);
        (document.head || document.documentElement).appendChild(script);
    });
}

function parseGlobalAgents(raw: unknown[]): DetectedAgent[] {
    if (!Array.isArray(raw)) return [];

    const agents: DetectedAgent[] = [];
    for (const entry of raw) {
        if (!entry || typeof entry !== 'object') continue;
        const e = entry as Record<string, unknown>;

        if (typeof e.agent_key !== 'string' || !/^[0-9a-fA-F]{64}$/.test(e.agent_key)) continue;

        agents.push({
            agent_key: (e.agent_key as string).toLowerCase(),
            model_id: typeof e.model_id === 'string' ? e.model_id : undefined,
            creator_org: typeof e.creator_org === 'string' ? e.creator_org : undefined,
            deployer_org: typeof e.deployer_org === 'string' ? e.deployer_org : undefined,
            capabilities: Array.isArray(e.capabilities) ? e.capabilities : undefined,
            source: 'global',
        });
    }
    return agents;
}

/**
 * Scan <script data-gns-aip> elements.
 *
 * Expected format:
 *   <script data-gns-aip="<hex64>"
 *           data-gns-aip-model="claude-sonnet"
 *           data-gns-aip-creator="anthropic.com">
 */
function scanScriptAttributes(): DetectedAgent[] {
    const agents: DetectedAgent[] = [];
    const scripts = document.querySelectorAll<HTMLScriptElement>('script[data-gns-aip]');

    for (const script of scripts) {
        const key = script.getAttribute('data-gns-aip');
        if (!key || !/^[0-9a-fA-F]{64}$/.test(key)) continue;

        agents.push({
            agent_key: key.toLowerCase(),
            model_id: script.getAttribute('data-gns-aip-model') || undefined,
            creator_org: script.getAttribute('data-gns-aip-creator') || undefined,
            deployer_org: script.getAttribute('data-gns-aip-deployer') || undefined,
            source: 'script',
        });
    }

    return agents;
}

// ============================================================
// SDK EVENT LISTENER
// ============================================================

/**
 * Listen for gns-aip-agent-declared CustomEvents from the GNS Auth SDK.
 *
 * When a website calls GNSAuth.declareAgent(manifest), the SDK fires
 * this event so the extension can pick it up.
 */
function listenForSdkDeclarations(): void {
    window.addEventListener('gns-aip-agent-declared', ((event: Event) => {
        const detail = (event as CustomEvent).detail;
        if (!detail || typeof detail !== 'object') return;

        const e = detail as Record<string, unknown>;
        if (typeof e.agent_key !== 'string' || !/^[0-9a-fA-F]{64}$/.test(e.agent_key)) return;

        const agent: DetectedAgent = {
            agent_key: (e.agent_key as string).toLowerCase(),
            model_id: typeof e.model_id === 'string' ? e.model_id : undefined,
            creator_org: typeof e.creator_org === 'string' ? e.creator_org : undefined,
            deployer_org: typeof e.deployer_org === 'string' ? e.deployer_org : undefined,
            capabilities: Array.isArray(e.capabilities) ? e.capabilities : undefined,
            source: 'sdk',
        };

        if (!detectedKeys.has(agent.agent_key)) {
            detectedKeys.add(agent.agent_key);
            notifyBackground([agent]);
        }
    }) as EventListener);
}

// ============================================================
// BACKGROUND NOTIFICATION
// ============================================================

/**
 * Send detected agents to the background for provenance verification.
 */
function notifyBackground(agents: DetectedAgent[]): void {
    if (agents.length === 0) return;

    chrome.runtime.sendMessage(
        {
            type: 'AIP_AGENTS_DETECTED',
            agents: agents.map(a => ({
                agent_key: a.agent_key,
                model_id: a.model_id,
                creator_org: a.creator_org,
                deployer_org: a.deployer_org,
                capabilities: a.capabilities,
            })),
        },
        () => {
            // Ignore response and runtime errors (background handles it)
            if (chrome.runtime.lastError) { /* expected on non-HTTPS pages */ }
        },
    );
}

// ============================================================
// MUTATION OBSERVER (SPA support)
// ============================================================

let observer: MutationObserver | null = null;

/**
 * Watch for dynamically added agent declarations.
 * SPAs may inject meta tags or script elements after initial load.
 */
function startObserver(): void {
    if (observer) return;

    let debounceTimer: ReturnType<typeof setTimeout>;

    observer = new MutationObserver(() => {
        clearTimeout(debounceTimer);
        debounceTimer = setTimeout(() => {
            runDetectionScan();
        }, 500);
    });

    observer.observe(document.documentElement, {
        childList: true,
        subtree: true,
        // Only watch for added nodes (meta tags, scripts)
        // Attribute changes are not needed for initial detection
    });
}

// ============================================================
// MAIN SCAN
// ============================================================

/**
 * Run all detection methods and notify background of new agents.
 */
async function runDetectionScan(): Promise<void> {
    const allAgents: DetectedAgent[] = [];

    // Synchronous scans
    allAgents.push(...scanMetaTags());
    allAgents.push(...scanScriptAttributes());

    // Async scan (global variable via script injection)
    const globalAgents = await scanGlobalVariable();
    allAgents.push(...globalAgents);

    // Deduplicate and filter already-seen
    const newAgents: DetectedAgent[] = [];
    for (const agent of allAgents) {
        if (!detectedKeys.has(agent.agent_key)) {
            detectedKeys.add(agent.agent_key);
            newAgents.push(agent);
        }
    }

    if (newAgents.length > 0) {
        console.log(`[GNS AIP] Detected ${newAgents.length} agent(s) on page:`,
            newAgents.map(a => `${a.model_id || a.agent_key.slice(0, 12)}… (${a.source})`));
        notifyBackground(newAgents);
    }
}

// ============================================================
// INITIALIZATION
// ============================================================

/**
 * Initialize the AIP detector — called by content/index.ts on every page load.
 */
export function initAipDetector(): void {
    // Only run on HTTPS pages
    if (window.location.protocol !== 'https:') return;

    // Listen for SDK declarations (fires before scan)
    listenForSdkDeclarations();

    // Initial scan
    runDetectionScan().then(() => {
        initialScanDone = true;
    });

    // Watch for dynamically added agents (SPAs)
    startObserver();

    // Set DOM attribute for SDK detection
    document.documentElement.setAttribute('data-gns-aip-detector', 'active');
}
