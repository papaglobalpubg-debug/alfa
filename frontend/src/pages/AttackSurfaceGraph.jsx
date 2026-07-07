import React, { useEffect, useState, useMemo, useRef } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import api from '@/lib/api';
import { ArrowLeft, Camera, Network, Loader } from 'lucide-react';

import { graphNodeSize } from '@/lib/uiHelpers';

const GROUP_COLORS = {
  verified: '#ef4444',   // red
  claimable: '#10b981',  // emerald
  verify: '#f59e0b',     // amber
  active: '#3b82f6',     // blue
  dead: '#6b7280',       // gray
  cname: '#a78bfa',      // purple
  sub: '#71717a',
};

/**
 * Simple radial layout: highest-severity in center, layered outward.
 * We compute positions once, cache in state.
 */
function layoutRadial(nodes, edges) {
  const width = 900, height = 700;
  const cx = width / 2, cy = height / 2;

  // Group priority
  const groupOrder = ['verified', 'claimable', 'verify', 'active', 'dead', 'cname', 'sub'];
  const byGroup = {};
  groupOrder.forEach(g => byGroup[g] = []);
  nodes.forEach(n => {
    (byGroup[n.group] || byGroup.sub).push(n);
  });

  const positioned = {};
  // Center: verified + claimable
  const center = [...byGroup.verified, ...byGroup.claimable];
  center.forEach((n, i) => {
    const angle = (2 * Math.PI * i) / Math.max(1, center.length);
    positioned[n.id] = {
      ...n,
      x: cx + Math.cos(angle) * (center.length > 1 ? 60 : 0),
      y: cy + Math.sin(angle) * (center.length > 1 ? 60 : 0),
    };
  });

  // Ring 1: verify + active
  const ring1 = [...byGroup.verify, ...byGroup.active];
  const r1 = 180;
  ring1.forEach((n, i) => {
    const angle = (2 * Math.PI * i) / Math.max(1, ring1.length);
    positioned[n.id] = { ...n, x: cx + Math.cos(angle) * r1, y: cy + Math.sin(angle) * r1 };
  });

  // Ring 2: dead + cname targets
  const ring2 = [...byGroup.dead, ...byGroup.cname];
  const r2 = 310;
  ring2.forEach((n, i) => {
    const angle = (2 * Math.PI * i) / Math.max(1, ring2.length);
    positioned[n.id] = { ...n, x: cx + Math.cos(angle) * r2, y: cy + Math.sin(angle) * r2 };
  });

  // Others (sub) — outer ring
  const outer = byGroup.sub;
  const r3 = 420;
  outer.forEach((n, i) => {
    const angle = (2 * Math.PI * i) / Math.max(1, outer.length);
    positioned[n.id] = { ...n, x: cx + Math.cos(angle) * r3, y: cy + Math.sin(angle) * r3 };
  });

  return { positioned, width, height };
}

export default function AttackSurfaceGraph() {
  const { id } = useParams();
  const nav = useNavigate();
  const [graph, setGraph] = useState(null);
  const [hovered, setHovered] = useState(null);
  const [scale, setScale] = useState(1);
  const [tx, setTx] = useState(0);
  const [ty, setTy] = useState(0);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    api.getGraph(id).then(({ data }) => {
      setGraph(data);
      setLoading(false);
    });
  }, [id]);

  const layout = useMemo(() => {
    if (!graph) return null;
    return layoutRadial(graph.nodes, graph.edges);
  }, [graph]);

  const onWheel = (e) => {
    e.preventDefault();
    const dz = e.deltaY > 0 ? -0.1 : 0.1;
    setScale((s) => Math.max(0.2, Math.min(3, s + dz)));
  };

  const dragRef = useRef(null);
  const onMouseDown = (e) => {
    dragRef.current = { x: e.clientX - tx, y: e.clientY - ty };
  };
  const onMouseMove = (e) => {
    if (dragRef.current) {
      setTx(e.clientX - dragRef.current.x);
      setTy(e.clientY - dragRef.current.y);
    }
  };
  const onMouseUp = () => { dragRef.current = null; };

  if (loading) return <div className="text-zinc-500 mono p-8">Building graph...</div>;
  if (!graph || !layout) return null;

  return (
    <div data-testid="graph-container" className="space-y-4 max-w-7xl">
      <button onClick={() => nav(`/scan/${id}`)}
        className="flex items-center gap-1 text-xs text-zinc-500 hover:text-emerald-500 mono">
        <ArrowLeft className="w-3 h-3" /> Back to scan
      </button>
      <header className="flex items-center justify-between flex-wrap gap-2">
        <div>
          <h1 className="text-2xl font-display font-bold text-zinc-50 tracking-tight flex items-center gap-2">
            <Network className="w-5 h-5 text-emerald-500" strokeWidth={1.5} />
            Attack Surface Graph
          </h1>
          <div className="text-xs text-zinc-500 mono mt-1">
            {graph.node_count} nodes · {graph.edge_count} edges · Scroll to zoom · Drag to pan
          </div>
        </div>
        <div className="flex gap-3 text-xs mono flex-wrap">
          {Object.entries({
            verified: 'Verified TO', claimable: 'Claimable', verify: 'Verify Req',
            active: 'Active', dead: 'Dead', cname: 'CNAME hop',
          }).map(([k, label]) => (
            <div key={k} className="flex items-center gap-1">
              <span className="w-2 h-2 rounded-full" style={{ background: GROUP_COLORS[k] }}></span>
              <span className="text-zinc-500">{label}</span>
            </div>
          ))}
        </div>
      </header>

      <div className="bg-black border border-zinc-800 overflow-hidden" style={{ height: '75vh' }}
        onWheel={onWheel}
        onMouseDown={onMouseDown}
        onMouseMove={onMouseMove}
        onMouseUp={onMouseUp}
        onMouseLeave={onMouseUp}
      >
        <svg
          data-testid="graph-svg"
          width="100%" height="100%"
          viewBox={`0 0 ${layout.width} ${layout.height}`}
          style={{ cursor: dragRef.current ? 'grabbing' : 'grab' }}
        >
          <g transform={`translate(${tx},${ty}) scale(${scale})`}>
            {/* Edges */}
            {graph.edges.map((e, i) => {
              const src = layout.positioned[e.source];
              const dst = layout.positioned[e.target];
              if (!src || !dst) return null;
              return (
                <line key={`edge-${e.source}-${e.target}-${i}`} x1={src.x} y1={src.y} x2={dst.x} y2={dst.y}
                  stroke="#3f3f46" strokeWidth={0.8} opacity={hovered && hovered !== e.source && hovered !== e.target ? 0.15 : 0.6} />
              );
            })}
            {/* Nodes */}
            {graph.nodes.map((n) => {
              const p = layout.positioned[n.id];
              if (!p) return null;
              const color = GROUP_COLORS[n.group] || GROUP_COLORS.sub;
              const size = graphNodeSize(n.group);
              const isHovered = hovered === n.id;
              return (
                <g key={n.id}
                  onMouseEnter={() => setHovered(n.id)}
                  onMouseLeave={() => setHovered(null)}
                  style={{ cursor: 'pointer' }}
                >
                  <circle cx={p.x} cy={p.y} r={isHovered ? size + 4 : size}
                    fill={color} opacity={hovered && !isHovered ? 0.35 : 1}
                    stroke={n.group === 'verified' ? '#fff' : 'none'} strokeWidth={0.5} />
                  {(isHovered || n.group === 'verified' || n.group === 'claimable') && (
                    <text x={p.x + size + 6} y={p.y + 3}
                      fill="#e4e4e7" fontSize="9" fontFamily="JetBrains Mono, monospace">
                      {n.id.length > 40 ? n.id.slice(0, 37) + '...' : n.id}
                    </text>
                  )}
                </g>
              );
            })}
          </g>
        </svg>
      </div>

      {hovered && (() => {
        const n = graph.nodes.find(x => x.id === hovered);
        if (!n) return null;
        return (
          <div className="bg-zinc-900 border border-zinc-800 p-3 mono text-xs">
            <div className="text-zinc-50 font-semibold">{n.id}</div>
            <div className="text-zinc-500 mt-1">
              Group: <span style={{ color: GROUP_COLORS[n.group] }}>{n.group}</span>
              {n.meta?.classification && <> · Class: {n.meta.classification}</>}
              {n.meta?.service_name && <> · Service: {n.meta.service_name}</>}
              {n.meta?.http_status && <> · HTTP: {n.meta.http_status}</>}
            </div>
          </div>
        );
      })()}

      <div className="flex gap-2">
        <button onClick={() => { setScale(1); setTx(0); setTy(0); }}
          className="px-3 py-1.5 border border-zinc-800 text-zinc-400 hover:text-zinc-50 mono text-xs">
          Reset view
        </button>
      </div>
    </div>
  );
}
