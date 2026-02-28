/**
 * GNS Vault Extension — AI Agent Identity Card (React Component)
 *
 * Shows AI agent provenance verification for the current site.
 * Displays the three-layer chain (Creator → Deployer → Principal)
 * with shield tier indicators and jurisdiction badges.
 *
 * Renders inside IdentityTab, below the DnsSiteCard (or replaces it
 * when AI agents are detected on the page).
 *
 * Location: packages/vault-extension/src/popup/components/AgentCard.tsx
 *
 * @module vault-extension/popup/components/AgentCard
 */

import React, { useState, useEffect, useCallback } from 'react';
import { sendMessage, truncateKey } from '../helpers';
import type {
    AipTabData,
    AipVerificationResult,
    AipProvenanceLayer,
    AipShieldTier,
    AipJurisdictionBinding,
    AipDelegationCert,
} from '../../utils/messages';

// ============================================================
// SHIELD STYLES
// ============================================================

const SHIELD_STYLES: Record<AipShieldTier, {
    bg: string; border: string; text: string; icon: string; label: string;
}> = {
    green: {
        bg: '#ECFDF5', border: '#6EE7B7', text: '#065F46',
        icon: '🛡️', label: 'Verified Provenance',
    },
    amber: {
        bg: '#FFFBEB', border: '#FCD34D', text: '#92400E',
        icon: '⚠️', label: 'Partial Provenance',
    },
    red: {
        bg: '#FEF2F2', border: '#FCA5A5', text: '#991B1B',
        icon: '🔴', label: 'Unverified Agent',
    },
    unknown: {
        bg: '#F9FAFB', border: '#E5E7EB', text: '#6B7280',
        icon: '❓', label: 'Unknown',
    },
};

// ============================================================
// LAYER STYLES
// ============================================================

const LAYER_CONFIG: Record<number, { icon: string; color: string }> = {
    1: { icon: '🏭', color: '#6366F1' }, // Creator — indigo
    2: { icon: '🏢', color: '#0891B2' }, // Deployer — cyan
    3: { icon: '👤', color: '#059669' }, // Principal — emerald
};

// ============================================================
// MAIN COMPONENT
// ============================================================

export function AgentCard() {
    const [data, setData] = useState<AipTabData | null>(null);
    const [loading, setLoading] = useState(true);
    const [expandedAgent, setExpandedAgent] = useState<number | null>(null);
    const [refreshing, setRefreshing] = useState(false);

    const fetchAipData = useCallback(async () => {
        try {
            console.log('[AgentCard] fetchAipData called');
            const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
            console.log('[AgentCard] tab:', tab?.id, tab?.url);
            if (!tab?.id) {
                console.log('[AgentCard] No tab id, bailing');
                setLoading(false);
                return;
            }

            const res = await sendMessage<AipTabData | null>({
                type: 'AIP_GET_AGENTS',
                tabId: tab.id,
            } as any);

            console.log('[AgentCard] response:', JSON.stringify(res).slice(0, 200));

            if (res.success && res.data && res.data.agent_count > 0) {
                console.log('[AgentCard] Setting data! agents:', res.data.agent_count);
                setData(res.data);
                if (res.data.agents.length === 1) setExpandedAgent(0);
            } else {
                console.log('[AgentCard] No agents. success:', res.success, 'data:', !!res.data);
            }
        } catch (e) {
            console.error('[AgentCard] Error:', e);
        } finally {
            setLoading(false);
        }
    }, []);

    useEffect(() => {
        fetchAipData();
    }, [fetchAipData]);

    const handleRefresh = async () => {
        if (!data) return;
        setRefreshing(true);

        const res = await sendMessage<AipTabData>({
            type: 'AIP_VERIFY_CHAIN',
            domain: data.domain,
        } as any);

        if (res.success && res.data) {
            setData(res.data);
        }

        setRefreshing(false);
    };

    // --- Loading state ---
    if (loading) return null; // Don't show anything while loading

    // --- No agents ---
    if (!data || data.agent_count === 0) return null; // Don't render — DnsSiteCard handles non-AIP sites

    return (
        <div style={{ marginBottom: '12px' }}>
            {/* Header */}
            <div style={{
                display: 'flex', alignItems: 'center', justifyContent: 'space-between',
                marginBottom: '8px', padding: '0 2px',
            }}>
                <div style={{
                    fontSize: '11px', fontWeight: 600, color: '#374151',
                    letterSpacing: '0.3px', display: 'flex', alignItems: 'center', gap: '6px',
                }}>
                    <span style={{ fontSize: '13px' }}>🤖</span>
                    AI AGENTS ON THIS SITE
                    <span style={{
                        background: '#E5E7EB', borderRadius: '10px',
                        padding: '1px 6px', fontSize: '10px', color: '#6B7280',
                    }}>
                        {data.agent_count}
                    </span>
                </div>
                <button
                    onClick={handleRefresh}
                    disabled={refreshing}
                    title="Re-verify all agents"
                    style={{
                        background: 'none', border: 'none', cursor: 'pointer',
                        fontSize: '13px', opacity: refreshing ? 0.4 : 0.7,
                        padding: '2px 4px',
                    }}
                >
                    {refreshing ? '⏳' : '🔄'}
                </button>
            </div>

            {/* Agent Cards */}
            {data.agents.map((agent, idx) => (
                <AgentRow
                    key={agent.agent_key}
                    agent={agent}
                    expanded={expandedAgent === idx}
                    onToggle={() => setExpandedAgent(expandedAgent === idx ? null : idx)}
                />
            ))}

            {/* Timestamp */}
            <div style={{ fontSize: '9px', color: '#9CA3AF', textAlign: 'right', marginTop: '4px' }}>
                Checked: {new Date(data.checked_at).toLocaleTimeString()}
            </div>
        </div>
    );
}

// ============================================================
// SINGLE AGENT ROW
// ============================================================

function AgentRow({ agent, expanded, onToggle }: {
    agent: AipVerificationResult;
    expanded: boolean;
    onToggle: () => void;
}) {
    const shield = SHIELD_STYLES[agent.shield];
    const verifiedCount = agent.layers.filter(l => l.verified).length;

    return (
        <div style={{
            border: `1px solid ${shield.border}`,
            borderRadius: '8px',
            background: shield.bg,
            marginBottom: '6px',
            overflow: 'hidden',
            transition: 'all 0.15s ease',
        }}>
            {/* Collapsed header */}
            <div
                onClick={onToggle}
                style={{
                    display: 'flex', alignItems: 'center', gap: '8px',
                    padding: '10px 12px', cursor: 'pointer', userSelect: 'none',
                }}
            >
                {/* Shield icon */}
                <span style={{ fontSize: '16px' }}>{shield.icon}</span>

                {/* Agent info */}
                <div style={{ flex: 1, minWidth: 0 }}>
                    <div style={{ fontWeight: 600, fontSize: '12px', color: shield.text }}>
                        {agent.model_id || truncateKey(agent.agent_key, 8)}
                    </div>
                    <div style={{ fontSize: '10px', color: '#6B7280', marginTop: '1px' }}>
                        {agent.creator_org || 'Unknown creator'}
                        {' → '}
                        {agent.deployer_org}
                    </div>
                </div>

                {/* Provenance indicator */}
                <div style={{
                    display: 'flex', gap: '3px', alignItems: 'center',
                }}>
                    {agent.layers.map((layer) => (
                        <div
                            key={layer.layer}
                            title={`L${layer.layer}: ${layer.label} — ${layer.verified ? 'Verified' : 'Unverified'}`}
                            style={{
                                width: '8px', height: '8px', borderRadius: '50%',
                                background: layer.verified ? '#10B981' : '#D1D5DB',
                                border: `1px solid ${layer.verified ? '#059669' : '#9CA3AF'}`,
                            }}
                        />
                    ))}
                    <span style={{ fontSize: '10px', color: '#9CA3AF', marginLeft: '2px' }}>
                        {verifiedCount}/3
                    </span>
                </div>

                {/* Expand arrow */}
                <span style={{ fontSize: '10px', color: '#9CA3AF', marginLeft: '4px' }}>
                    {expanded ? '▼' : '▶'}
                </span>
            </div>

            {/* Expanded detail */}
            {expanded && (
                <div style={{
                    padding: '0 12px 12px',
                    borderTop: `1px solid ${shield.border}`,
                    paddingTop: '10px',
                }}>
                    {/* Three-layer provenance chain */}
                    <div style={{ marginBottom: '10px' }}>
                        {agent.layers.map((layer, idx) => (
                            <LayerRow
                                key={layer.layer}
                                layer={layer}
                                isLast={idx === agent.layers.length - 1}
                            />
                        ))}
                    </div>

                    {/* Jurisdiction badges */}
                    {agent.jurisdiction && Object.keys(agent.jurisdiction).length > 0 && (
                        <JurisdictionSection jurisdiction={agent.jurisdiction} />
                    )}

                    {/* Capabilities */}
                    {agent.capabilities && agent.capabilities.length > 0 && (
                        <div style={{ marginTop: '8px' }}>
                            <div style={{ fontSize: '10px', color: '#9CA3AF', marginBottom: '4px' }}>
                                Capabilities
                            </div>
                            <div style={{ display: 'flex', flexWrap: 'wrap', gap: '3px' }}>
                                {agent.capabilities.map((cap) => (
                                    <span key={cap} style={{
                                        fontSize: '10px', padding: '2px 6px',
                                        background: '#EFF6FF', color: '#1D4ED8',
                                        borderRadius: '4px', border: '1px solid #BFDBFE',
                                    }}>
                                        {cap}
                                    </span>
                                ))}
                            </div>
                        </div>
                    )}

                    {/* Delegation certificate summary */}
                    {agent.delegation && (
                        <DelegationSummary delegation={agent.delegation} />
                    )}

                    {/* Warnings */}
                    {agent.warnings.length > 0 && (
                        <div style={{
                            marginTop: '8px', padding: '6px 8px',
                            background: '#FEF3C7', borderRadius: '4px',
                            fontSize: '10px', color: '#92400E', lineHeight: 1.4,
                        }}>
                            {agent.warnings.map((w, i) => (
                                <div key={i}>⚠️ {w}</div>
                            ))}
                        </div>
                    )}

                    {/* Agent key */}
                    <div style={{
                        fontSize: '9px', color: '#9CA3AF', marginTop: '8px',
                        fontFamily: 'monospace', wordBreak: 'break-all',
                    }}>
                        Agent: {agent.agent_key}
                    </div>
                </div>
            )}
        </div>
    );
}

// ============================================================
// PROVENANCE LAYER ROW
// ============================================================

function LayerRow({ layer, isLast }: { layer: AipProvenanceLayer; isLast: boolean }) {
    const config = LAYER_CONFIG[layer.layer] || { icon: '?', color: '#6B7280' };

    return (
        <div style={{ display: 'flex', gap: '8px', position: 'relative' }}>
            {/* Connector line */}
            {!isLast && (
                <div style={{
                    position: 'absolute', left: '10px', top: '22px',
                    width: '1px', height: 'calc(100% - 6px)',
                    background: layer.verified ? '#D1FAE5' : '#E5E7EB',
                }} />
            )}

            {/* Layer icon */}
            <div style={{
                width: '22px', height: '22px', borderRadius: '50%',
                background: layer.verified ? '#D1FAE5' : '#F3F4F6',
                border: `1.5px solid ${layer.verified ? '#10B981' : '#D1D5DB'}`,
                display: 'flex', alignItems: 'center', justifyContent: 'center',
                fontSize: '11px', flexShrink: 0, zIndex: 1,
            }}>
                {config.icon}
            </div>

            {/* Layer content */}
            <div style={{
                flex: 1, paddingBottom: isLast ? 0 : '8px',
                minWidth: 0,
            }}>
                <div style={{
                    display: 'flex', alignItems: 'center', gap: '6px',
                }}>
                    <span style={{
                        fontSize: '11px', fontWeight: 600,
                        color: layer.verified ? '#065F46' : '#6B7280',
                    }}>
                        L{layer.layer}: {layer.label}
                    </span>
                    {layer.verified && (
                        <span style={{
                            fontSize: '9px', padding: '1px 4px',
                            background: '#D1FAE5', color: '#065F46',
                            borderRadius: '3px', fontWeight: 600,
                        }}>
                            ✓
                        </span>
                    )}
                    {layer.dns_verified && (
                        <span style={{
                            fontSize: '9px', padding: '1px 4px',
                            background: '#EFF6FF', color: '#1D4ED8',
                            borderRadius: '3px',
                        }}>
                            DNS
                        </span>
                    )}
                </div>

                {layer.org && (
                    <div style={{ fontSize: '10px', color: '#374151', marginTop: '1px' }}>
                        {layer.org}
                    </div>
                )}

                {layer.detail && (
                    <div style={{
                        fontSize: '10px', color: '#6B7280',
                        marginTop: '1px', lineHeight: 1.3,
                    }}>
                        {layer.detail}
                    </div>
                )}

                {/* Trust score bar (Layer 3) */}
                {layer.trust_score !== undefined && (
                    <div style={{ marginTop: '4px' }}>
                        <div style={{
                            display: 'flex', justifyContent: 'space-between',
                            fontSize: '9px', color: '#6B7280', marginBottom: '2px',
                        }}>
                            <span>Trust Score</span>
                            <span>{layer.trust_score}/100</span>
                        </div>
                        <div style={{
                            width: '100%', height: '4px',
                            background: '#E5E7EB', borderRadius: '2px', overflow: 'hidden',
                        }}>
                            <div style={{
                                width: `${layer.trust_score}%`, height: '100%',
                                background: layer.trust_score >= 85 ? '#10B981'
                                    : layer.trust_score >= 50 ? '#F59E0B'
                                        : '#EF4444',
                                borderRadius: '2px',
                                transition: 'width 0.3s ease',
                            }} />
                        </div>
                    </div>
                )}
            </div>
        </div>
    );
}

// ============================================================
// JURISDICTION SECTION
// ============================================================

function JurisdictionSection({ jurisdiction }: {
    jurisdiction: Record<string, AipJurisdictionBinding>;
}) {
    return (
        <div>
            <div style={{ fontSize: '10px', color: '#9CA3AF', marginBottom: '4px' }}>
                Jurisdiction Binding
            </div>
            <div style={{ display: 'flex', flexWrap: 'wrap', gap: '3px' }}>
                {Object.entries(jurisdiction).map(([key, binding]) => (
                    <div key={key} style={{
                        display: 'flex', flexDirection: 'column', gap: '2px',
                        padding: '4px 6px',
                        background: binding.risk_class === 'high' ? '#FEF2F2'
                            : binding.risk_class === 'medium' ? '#FFFBEB'
                                : '#F0FDF4',
                        border: `1px solid ${binding.risk_class === 'high' ? '#FCA5A5'
                            : binding.risk_class === 'medium' ? '#FCD34D'
                                : '#BBF7D0'
                            }`,
                        borderRadius: '4px',
                    }}>
                        <div style={{ display: 'flex', gap: '4px', alignItems: 'center' }}>
                            {binding.risk_class && (
                                <span style={{
                                    fontSize: '8px', fontWeight: 700, textTransform: 'uppercase',
                                    color: binding.risk_class === 'high' ? '#991B1B'
                                        : binding.risk_class === 'medium' ? '#92400E'
                                            : '#166534',
                                }}>
                                    {binding.risk_class}
                                </span>
                            )}
                            {binding.disclosure_required && (
                                <span style={{ fontSize: '8px', color: '#6B7280' }}>📋</span>
                            )}
                        </div>
                        {binding.regulations.map((reg) => (
                            <span key={reg} style={{
                                fontSize: '9px', color: '#374151', fontWeight: 500,
                            }}>
                                {reg}
                            </span>
                        ))}
                    </div>
                ))}
            </div>
        </div>
    );
}

// ============================================================
// DELEGATION SUMMARY
// ============================================================

function DelegationSummary({ delegation }: { delegation: AipDelegationCert }) {
    const isValid = delegation.not_after
        ? new Date(delegation.not_after).getTime() > Date.now()
        : true;

    return (
        <div style={{
            marginTop: '8px', padding: '6px 8px',
            background: isValid ? '#F0FDF4' : '#FEF2F2',
            borderRadius: '4px', border: `1px solid ${isValid ? '#BBF7D0' : '#FCA5A5'}`,
        }}>
            <div style={{
                fontSize: '10px', fontWeight: 600,
                color: isValid ? '#166534' : '#991B1B',
                marginBottom: '4px',
            }}>
                Delegation Certificate {isValid ? '✓' : '✗ Expired'}
            </div>
            <div style={{
                display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '2px',
                fontSize: '9px', color: '#374151',
            }}>
                {delegation.trust_score !== undefined && (
                    <div>Trust: <strong>{delegation.trust_score}/100</strong></div>
                )}
                {delegation.not_after && (
                    <div>Expires: <strong>{new Date(delegation.not_after).toLocaleDateString()}</strong></div>
                )}
                {delegation.capabilities.length > 0 && (
                    <div>Scope: <strong>{delegation.capabilities.join(', ')}</strong></div>
                )}
                {delegation.max_subdelegation !== undefined && (
                    <div>Sub-delegation: <strong>{delegation.max_subdelegation > 0 ? `depth ${delegation.max_subdelegation}` : 'none'}</strong></div>
                )}
                {delegation.poh_alpha !== undefined && (
                    <div>PoH α: <strong>{delegation.poh_alpha.toFixed(2)}</strong></div>
                )}
                {delegation.territory_cells.length > 0 && (
                    <div>Territory: <strong>{delegation.territory_cells.length} cell{delegation.territory_cells.length > 1 ? 's' : ''}</strong></div>
                )}
            </div>
        </div>
    );
}