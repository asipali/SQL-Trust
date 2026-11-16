import { useEffect, useRef, useState } from 'react'
import * as THREE from 'three'
import { ShieldAlert, Activity } from 'lucide-react'
import { SecurityAlert, SecurityEvent } from '../../types/security'

export interface ThreatActivity3DProps {
  alerts?: SecurityAlert[]
  events?: SecurityEvent[]
  height?: string
  onSelectAlert?: (alert: SecurityAlert) => void
}

export function ThreatActivity3D({
  alerts = [],
  events: _events = [],
  height = '350px',
  onSelectAlert
}: ThreatActivity3DProps) {
  const containerRef = useRef<HTMLDivElement>(null)
  const [selectedAlert, setSelectedAlert] = useState<SecurityAlert | null>(null)
  const [hoveredAlert, setHoveredAlert] = useState<SecurityAlert | null>(null)

  useEffect(() => {
    const container = containerRef.current
    if (!container) return

    // Scene setup
    const scene = new THREE.Scene()
    scene.background = new THREE.Color(0x0f172a)

    const width = container.clientWidth || 600
    const heightPx = parseInt(height, 10) || 350
    const camera = new THREE.PerspectiveCamera(45, width / heightPx, 0.1, 1000)
    camera.position.set(0, 5, 12)
    camera.lookAt(0, 0, 0)

    const renderer = new THREE.WebGLRenderer({ antialias: true, alpha: true })
    renderer.setSize(width, heightPx)
    renderer.setPixelRatio(Math.min(window.devicePixelRatio, 2))
    container.innerHTML = ''
    container.appendChild(renderer.domElement)

    // Lighting
    const ambientLight = new THREE.AmbientLight(0xffffff, 0.6)
    scene.add(ambientLight)

    const dirLight = new THREE.DirectionalLight(0x38bdf8, 1.2)
    dirLight.position.set(5, 10, 7)
    scene.add(dirLight)

    // Central Sphere (SQL Core)
    const coreGeom = new THREE.SphereGeometry(1.2, 32, 32)
    const coreMat = new THREE.MeshStandardMaterial({
      color: 0x0ea5e9,
      roughness: 0.3,
      metalness: 0.8,
      emissive: 0x0284c7,
      emissiveIntensity: 0.4
    })
    const coreMesh = new THREE.Mesh(coreGeom, coreMat)
    scene.add(coreMesh)

    // Radar Rings
    const ringMat = new THREE.LineBasicMaterial({ color: 0x334155, transparent: true, opacity: 0.5 })
    for (let r = 2.5; r <= 6.5; r += 1.5) {
      const ringGeom = new THREE.BufferGeometry()
      const pts: THREE.Vector3[] = []
      for (let i = 0; i <= 64; i++) {
        const theta = (i / 64) * Math.PI * 2
        pts.push(new THREE.Vector3(Math.cos(theta) * r, 0, Math.sin(theta) * r))
      }
      ringGeom.setFromPoints(pts)
      const ringLine = new THREE.Line(ringGeom, ringMat)
      scene.add(ringLine)
    }

    // Threat Nodes representation
    const nodeMeshes: THREE.Mesh[] = []
    const alertCount = Math.min(alerts.length, 12)
    for (let i = 0; i < alertCount; i++) {
      const alt = alerts[i]
      const angle = (i / alertCount) * Math.PI * 2
      const radius = alt.severity === 'CRITICAL' ? 3.0 : alt.severity === 'HIGH' ? 4.5 : 6.0
      const x = Math.cos(angle) * radius
      const z = Math.sin(angle) * radius
      const y = Math.sin(i * 1.5) * 0.8

      const isCritical = alt.severity === 'CRITICAL'
      const nodeGeom = new THREE.SphereGeometry(isCritical ? 0.35 : 0.25, 16, 16)
      const nodeMat = new THREE.MeshStandardMaterial({
        color: isCritical ? 0xf43f5e : 0xf59e0b,
        emissive: isCritical ? 0xe11d48 : 0xd97706,
        emissiveIntensity: 0.7,
        roughness: 0.2
      })

      const mesh = new THREE.Mesh(nodeGeom, nodeMat)
      mesh.position.set(x, y, z)
      mesh.userData = { alert: alt }
      scene.add(mesh)
      nodeMeshes.push(mesh)

      // Trajectory connection line to core
      const lineGeom = new THREE.BufferGeometry().setFromPoints([
        new THREE.Vector3(0, 0, 0),
        new THREE.Vector3(x, y, z)
      ])
      const lineMat = new THREE.LineBasicMaterial({
        color: isCritical ? 0xf43f5e : 0xf59e0b,
        transparent: true,
        opacity: 0.35
      })
      const line = new THREE.Line(lineGeom, lineMat)
      scene.add(line)
    }

    // Raycasting for interaction
    const raycaster = new THREE.Raycaster()
    const mouse = new THREE.Vector2()

    const handlePointerMove = (e: MouseEvent) => {
      const rect = renderer.domElement.getBoundingClientRect()
      mouse.x = ((e.clientX - rect.left) / rect.width) * 2 - 1
      mouse.y = -((e.clientY - rect.top) / rect.height) * 2 + 1

      raycaster.setFromCamera(mouse, camera)
      const intersects = raycaster.intersectObjects(nodeMeshes)
      if (intersects.length > 0) {
        const alt = intersects[0].object.userData.alert as SecurityAlert
        setHoveredAlert(alt)
        renderer.domElement.style.cursor = 'pointer'
      } else {
        setHoveredAlert(null)
        renderer.domElement.style.cursor = 'default'
      }
    }

    const handleClick = (e: MouseEvent) => {
      const rect = renderer.domElement.getBoundingClientRect()
      mouse.x = ((e.clientX - rect.left) / rect.width) * 2 - 1
      mouse.y = -((e.clientY - rect.top) / rect.height) * 2 + 1

      raycaster.setFromCamera(mouse, camera)
      const intersects = raycaster.intersectObjects(nodeMeshes)
      if (intersects.length > 0) {
        const alt = intersects[0].object.userData.alert as SecurityAlert
        setSelectedAlert(alt)
        onSelectAlert?.(alt)
      }
    }

    renderer.domElement.addEventListener('mousemove', handlePointerMove)
    renderer.domElement.addEventListener('click', handleClick)

    // Animation loop
    let animId: number
    const animate = () => {
      animId = requestAnimationFrame(animate)
      coreMesh.rotation.y += 0.005
      renderer.render(scene, camera)
    }
    animate()

    // Handle resize
    const handleResize = () => {
      if (!container) return
      const w = container.clientWidth
      camera.aspect = w / heightPx
      camera.updateProjectionMatrix()
      renderer.setSize(w, heightPx)
    }
    window.addEventListener('resize', handleResize)

    return () => {
      cancelAnimationFrame(animId)
      window.removeEventListener('resize', handleResize)
      renderer.domElement.removeEventListener('mousemove', handlePointerMove)
      renderer.domElement.removeEventListener('click', handleClick)
      if (container.contains(renderer.domElement)) {
        container.removeChild(renderer.domElement)
      }
      renderer.dispose()
    }
  }, [alerts, height, onSelectAlert])

  return (
    <div className="relative rounded-xl overflow-hidden border border-slate-800 bg-slate-900 shadow-xl">
      {/* 3D WebGL Canvas */}
      <div ref={containerRef} style={{ height }} className="w-full" />

      {/* Overlay UI Controls */}
      <div className="absolute top-3 left-3 flex items-center gap-2 px-3 py-1.5 rounded-lg bg-slate-900/80 backdrop-blur-md border border-slate-700/60 text-xs font-mono text-slate-300">
        <Activity className="w-3.5 h-3.5 text-cyan-400 animate-pulse" />
        <span>Live Threat Radar ({alerts.length} Detected)</span>
      </div>

      {/* Hover Info Card */}
      {hoveredAlert && (
        <div className="absolute bottom-3 left-3 max-w-sm p-3 rounded-lg bg-slate-900/90 backdrop-blur-md border border-slate-700 text-xs text-slate-200 shadow-2xl">
          <div className="flex items-center gap-2 mb-1">
            <span
              className={`px-1.5 py-0.5 rounded text-[10px] font-bold ${
                hoveredAlert.severity === 'CRITICAL'
                  ? 'bg-rose-500/20 text-rose-300 border border-rose-500/30'
                  : 'bg-amber-500/20 text-amber-300 border border-amber-500/30'
              }`}
            >
              {hoveredAlert.severity}
            </span>
            <span className="font-semibold text-white truncate">{hoveredAlert.title}</span>
          </div>
          <p className="text-[11px] text-slate-400 line-clamp-2">{hoveredAlert.description}</p>
        </div>
      )}

      {/* Selected Alert Modal/Overlay */}
      {selectedAlert && (
        <div className="absolute top-3 right-3 max-w-xs p-3 rounded-lg bg-slate-950/95 border border-slate-700 text-xs text-slate-200 shadow-2xl space-y-2">
          <div className="flex items-center justify-between border-b border-slate-800 pb-1.5">
            <span className="font-bold text-white flex items-center gap-1.5">
              <ShieldAlert className="w-3.5 h-3.5 text-rose-400" />
              Threat Inspection
            </span>
            <button
              onClick={() => setSelectedAlert(null)}
              className="text-slate-400 hover:text-white text-xs px-1"
            >
              ✕
            </button>
          </div>
          <div>
            <div className="text-[11px] font-semibold text-slate-300">{selectedAlert.title}</div>
            <div className="text-[10px] text-slate-400 font-mono mt-0.5">
              Rule ID: {selectedAlert.rule_id}
            </div>
            <div className="text-[11px] text-slate-400 mt-1 line-clamp-2">{selectedAlert.description}</div>
          </div>
          <div className="pt-1.5 border-t border-slate-800 flex justify-between text-[10px] text-slate-400">
            <span>Status: {selectedAlert.status}</span>
            <span>Target: {selectedAlert.target_object || 'SQLEXPRESS'}</span>
          </div>
        </div>
      )}
    </div>
  )
}
