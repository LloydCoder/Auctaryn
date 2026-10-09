import { useState, useEffect } from 'react'
import { Network, Upload, AlertTriangle, Shield } from 'lucide-react'
import { fetchThreatFadeStatus, fetchDetections } from '../utils/api'

const SEVERITY_STYLES = {
  critical: { color: 'text-red-400', bg: 'bg-red-400/10', border: 'border-red-400/30' },
  high: { color: 'text-orange-400', bg: 'bg-orange-400/10', border: 'border-orange-400/30' },
  medium: { color: 'text-amber-400', bg: 'bg-amber-400/10', border: 'border-amber-400/30' },
  low: { color: 'text-blue-400', bg: 'bg-blue-400/10', border: 'border-blue-400/30' },
  info: { color: 'text-gray-400', bg: 'bg-gray-400/10', border: 'border-gray-400/30' },
}

export default function ThreatFadePanel() {
  const [status, setStatus] = useState(null)
  const [detections, setDetections] = useState([])

  useEffect(() => {
    fetchThreatFadeStatus().then(setStatus).catch(() => {})
    fetchDetections().then(setDetections).catch(() => {})
  }, [])

  return (
    <div className="space-y-6">
      {/* Status card */}
      <div className="bg-[#111827] border border-gray-800/50 rounded-xl p-6">
        <div className="flex items-center gap-3 mb-4">
          <Network className="w-5 h-5 text-purple-400" />
          <h3 className="text-sm font-semibold text-gray-200 uppercase tracking-wider">
            ThreatFade Oracle
          </h3>
          <span className="ml-auto px-2 py-0.5 text-xs font-mono text-gray-500 bg-gray-800/50 rounded">
            v{status?.threatfade_version || '0.2.0-beta'}
          </span>
        </div>

        <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
          <div>
            <div className={`text-xl font-bold ${status?.connected ? 'text-emerald-400' : 'text-gray-500'}`}>
              {status?.connected ? 'Connected' : 'Offline'}
            </div>
            <div className="text-xs text-gray-500">Service Status</div>
          </div>
          <div>
            <div className="text-xl font-bold text-gray-200">{detections.length}</div>
            <div className="text-xs text-gray-500">Detections</div>
          </div>
          <div>
            <div className="text-xl font-bold text-gray-200">0%</div>
            <div className="text-xs text-gray-500">False Positive Rate</div>
          </div>
          <div>
            <div className="text-xl font-bold text-gray-200">3</div>
            <div className="text-xs text-gray-500">MITRE TTPs Mapped</div>
          </div>
        </div>
      </div>

      {/* PCAP Upload */}
      <div className="bg-[#111827] border border-gray-800/50 rounded-xl p-6">
        <h4 className="text-xs font-medium text-gray-400 uppercase tracking-wider mb-4">
          Analyze Network Capture
        </h4>
        <div className="border-2 border-dashed border-gray-700 rounded-xl p-8 text-center hover:border-purple-500/50 transition-colors cursor-pointer">
          <Upload className="w-8 h-8 text-gray-600 mx-auto mb-3" />
          <p className="text-sm text-gray-400">Drop a PCAP file here or click to upload</p>
          <p className="text-xs text-gray-600 mt-1">Supports .pcap and .pcapng files</p>
        </div>
      </div>

      {/* Detections list */}
      <div className="bg-[#111827] border border-gray-800/50 rounded-xl p-6">
        <h4 className="text-xs font-medium text-gray-400 uppercase tracking-wider mb-4">
          Recent Detections
        </h4>

        {detections.length === 0 ? (
          <div className="text-center py-12 text-gray-600">
            <Shield className="w-10 h-10 mx-auto mb-3 opacity-30" />
            <p className="text-sm">No threats detected.</p>
            <p className="text-xs mt-1">Upload a PCAP file to begin analysis.</p>
          </div>
        ) : (
          <div className="space-y-3">
            {detections.map((det, i) => {
              const sev = SEVERITY_STYLES[det.severity] || SEVERITY_STYLES.info
              return (
                <div key={i} className={`p-4 rounded-lg border ${sev.border} ${sev.bg}`}>
                  <div className="flex items-center justify-between mb-2">
                    <span className={`text-sm font-semibold uppercase ${sev.color}`}>
                      {det.severity}
                    </span>
                    <span className="text-xs text-gray-500 font-mono">
                      z-score: {det.z_score?.toFixed(2)}
                    </span>
                  </div>
                  <div className="text-xs text-gray-400">
                    Score: {det.score?.toFixed(3)} | Entropy: {det.entropy?.toFixed(3)} | Drop: {(det.drop_ratio * 100)?.toFixed(1)}%
                  </div>
                  {det.mitre_ttps?.length > 0 && (
                    <div className="flex gap-2 mt-2">
                      {det.mitre_ttps.map(ttp => (
                        <span key={ttp} className="px-2 py-0.5 text-xs font-mono text-purple-400 bg-purple-400/10 rounded">
                          {ttp}
                        </span>
                      ))}
                    </div>
                  )}
                </div>
              )
            })}
          </div>
        )}
      </div>
    </div>
  )
}
