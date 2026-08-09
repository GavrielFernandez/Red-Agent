/**
 * RedAgent 3D Tactical Visualization
 *
 * High-performance attack graph renderer with deterministic layout,
 * timeline replay support, path mode, adaptive quality controls,
 * instanced rendering, and mission snapshot export support.
 */

class AttackVisualization {
    constructor(containerId) {
        this.container = document.getElementById(containerId);
        if (!this.container) {
            console.error(`Container #${containerId} not found`);
            return;
        }

        this.nodes = new Map();
        this.edges = new Map();
        this.nodeObjects = new Map();
        this.edgeObjects = new Map();
        this.edgeCurves = new Map();
        this.particleSystems = new Map();
        this.geometryCache = new Map();
        this.nodePositions = new Map();

        this.instancedMode = false;
        this.instancedThreshold = 280;
        this.instancedGroups = new Map();
        this.instancedNodeLookup = new Map();
        this.instancedPicker = [];

        this.scene = null;
        this.camera = null;
        this.renderer = null;
        this.controls = null;
        this.raycaster = null;
        this.mouse = null;
        this.composer = null;
        this.bloomPass = null;

        this.selectedNode = null;
        this.hoveredNode = null;
        this.pathMode = false;
        this.pathSource = "";
        this.pathTarget = "";

        this.animationHandle = null;
        this.lastFrameTime = performance.now();
        this.fpsSamples = [];
        this.qualityLevel = "high";
        this.rotationSpeed = 0.002;
        this.labelsVisible = true;

        this.colors = {
            target: 0x4a90d9,
            host: 0x50c878,
            service: 0xffd700,
            vulnerability: 0xff6b6b,
            exploit: 0x8b0000,
            data: 0x9370db,
            edge: {
                discovered: 0x475569,
                attacking: 0xff4444,
                exploited: 0x8b0000,
            },
            severity: {
                critical: 0xff0000,
                high: 0xff6600,
                medium: 0xffcc00,
                low: 0x00cc00,
                info: 0x0099ff,
            },
            mutedNode: 0x313746,
            mutedEdge: 0x2b3140,
            highlight: 0x5ef2ff,
        };

        this.init();
    }

    init() {
        this.scene = new THREE.Scene();
        this.scene.background = new THREE.Color(0x070b12);
        this.scene.fog = new THREE.Fog(0x070b12, 140, 560);

        const aspect = this.container.clientWidth / this.container.clientHeight;
        this.camera = new THREE.PerspectiveCamera(68, aspect, 0.1, 1500);
        this.camera.position.set(0, -180, 170);

        this.renderer = new THREE.WebGLRenderer({ antialias: true, alpha: true, preserveDrawingBuffer: true });
        this.renderer.setSize(this.container.clientWidth, this.container.clientHeight);
        this.renderer.setPixelRatio(Math.min(window.devicePixelRatio || 1, 2));
        this.renderer.outputEncoding = THREE.sRGBEncoding;
        this.container.appendChild(this.renderer.domElement);

        this.controls = new THREE.OrbitControls(this.camera, this.renderer.domElement);
        this.controls.enableDamping = true;
        this.controls.dampingFactor = 0.06;
        this.controls.screenSpacePanning = true;
        this.controls.minDistance = 45;
        this.controls.maxDistance = 760;

        this.raycaster = new THREE.Raycaster();
        this.mouse = new THREE.Vector2();

        this.setupLighting();
        this.setupPostProcessing();

        const grid = new THREE.GridHelper(360, 36, 0x1f2b3d, 0x0f1622);
        grid.rotation.x = Math.PI / 2;
        this.scene.add(grid);

        window.addEventListener("resize", () => this.onResize());
        this.renderer.domElement.addEventListener("mousemove", (e) => this.onMouseMove(e));
        this.renderer.domElement.addEventListener("click", () => this.onClick());

        this.animate();
    }

    setupLighting() {
        const ambient = new THREE.AmbientLight(0x3a4b63, 0.55);
        this.scene.add(ambient);

        const dirMain = new THREE.DirectionalLight(0xffffff, 0.78);
        dirMain.position.set(120, 90, 130);
        this.scene.add(dirMain);

        const dirFill = new THREE.DirectionalLight(0x4a90d9, 0.28);
        dirFill.position.set(-110, -140, -80);
        this.scene.add(dirFill);

        const alertLight = new THREE.PointLight(0xff2f2f, 0.25, 280);
        alertLight.position.set(45, -60, 85);
        this.scene.add(alertLight);

        const successLight = new THREE.PointLight(0x00c26f, 0.2, 260);
        successLight.position.set(-65, 75, 55);
        this.scene.add(successLight);
    }

    setupPostProcessing() {
        if (!THREE.EffectComposer || !THREE.RenderPass || !THREE.UnrealBloomPass || !THREE.ShaderPass || !THREE.CopyShader) {
            console.warn("Post-processing shaders not available, using standard rendering");
            return;
        }

        try {
            this.composer = new THREE.EffectComposer(this.renderer);
            const renderPass = new THREE.RenderPass(this.scene, this.camera);
            this.composer.addPass(renderPass);

            this.bloomPass = new THREE.UnrealBloomPass(
                new THREE.Vector2(this.container.clientWidth, this.container.clientHeight),
                0.55,
                0.4,
                0.85,
            );
            this.composer.addPass(this.bloomPass);
        } catch (err) {
            console.warn("Failed to initialize post-processing:", err.message);
            this.composer = null;
            this.bloomPass = null;
        }
    }

    setBloomIntensity(intensity) {
        if (!this.bloomPass) return;
        this.bloomPass.strength = Math.max(0.2, Math.min(1.8, Number(intensity || 0.55)));
    }

    hashString(text) {
        let hash = 0;
        const value = String(text || "");
        for (let i = 0; i < value.length; i += 1) {
            hash = ((hash << 5) - hash) + value.charCodeAt(i);
            hash |= 0;
        }
        return Math.abs(hash);
    }

    generateDeterministicLayout(graph) {
        const byType = {
            target: [],
            host: [],
            service: [],
            vulnerability: [],
            exploit: [],
            data: [],
            other: [],
        };

        const nodes = Array.isArray(graph?.nodes) ? graph.nodes : [];
        nodes.forEach((node) => {
            const type = byType[node.type] ? node.type : "other";
            byType[type].push(node);
        });

        const rings = {
            target: { radius: 0, z: 0 },
            host: { radius: 52, z: 18 },
            service: { radius: 92, z: 40 },
            vulnerability: { radius: 126, z: 66 },
            exploit: { radius: 156, z: 94 },
            data: { radius: 188, z: 120 },
            other: { radius: 76, z: 52 },
        };

        const positioned = [];
        Object.keys(byType).forEach((type) => {
            const list = byType[type].sort((a, b) => String(a.id).localeCompare(String(b.id)));
            const ring = rings[type];
            const count = Math.max(list.length, 1);

            list.forEach((node, index) => {
                const h = this.hashString(node.id);
                const angleOffset = (h % 360) * (Math.PI / 180);
                const angle = (index / count) * Math.PI * 2 + angleOffset * 0.18;
                const jitter = ((h % 17) - 8) * 0.8;
                const radial = ring.radius + jitter;
                const x = ring.radius === 0 ? 0 : Math.cos(angle) * radial;
                const y = ring.radius === 0 ? 0 : Math.sin(angle) * radial;
                const z = ring.z + (((h % 11) - 5) * 1.2);

                positioned.push({
                    ...node,
                    position: { x, y, z },
                });
            });
        });

        return {
            nodes: positioned,
            edges: Array.isArray(graph?.edges) ? graph.edges : [],
        };
    }

    getNodeGeometry(type, scale = 1) {
        const key = `${type}:${scale}`;
        if (this.geometryCache.has(key)) {
            return this.geometryCache.get(key);
        }

        const size = this.getNodeSize(type) * scale;
        let geometry;
        switch (type) {
            case "target":
                geometry = new THREE.OctahedronGeometry(size);
                break;
            case "host":
                geometry = new THREE.BoxGeometry(size, size, size);
                break;
            case "service":
                geometry = new THREE.CylinderGeometry(size * 0.7, size, size, 6);
                break;
            case "vulnerability":
                geometry = new THREE.TetrahedronGeometry(size);
                break;
            case "exploit":
                geometry = new THREE.IcosahedronGeometry(size);
                break;
            case "data":
                geometry = new THREE.TorusGeometry(size * 0.7, size * 0.3, 8, 16);
                break;
            default:
                geometry = new THREE.SphereGeometry(size);
                break;
        }

        this.geometryCache.set(key, geometry);
        return geometry;
    }

    getNodeSize(type) {
        const sizes = {
            target: 8,
            host: 6,
            service: 4,
            vulnerability: 5,
            exploit: 7,
            data: 4,
        };
        return sizes[type] || 5;
    }

    getNodeColor(nodeData) {
        const severity = String(nodeData?.severity || "").toLowerCase();
        if (severity && severity !== "info") {
            return this.colors.severity[severity] || this.colors[nodeData.type] || 0x888888;
        }
        return this.colors[nodeData.type] || 0x888888;
    }

    createLabel(text) {
        const canvas = document.createElement("canvas");
        const context = canvas.getContext("2d");
        canvas.width = 256;
        canvas.height = 64;

        context.fillStyle = "rgba(5, 9, 15, 0.78)";
        context.fillRect(0, 0, canvas.width, canvas.height);

        context.font = "600 22px Segoe UI";
        context.fillStyle = "#eff7ff";
        context.textAlign = "center";
        context.fillText(String(text || "").substring(0, 24), canvas.width / 2, canvas.height / 2 + 8);

        const texture = new THREE.CanvasTexture(canvas);
        const material = new THREE.SpriteMaterial({ map: texture, transparent: true });
        const sprite = new THREE.Sprite(material);
        sprite.scale.set(30, 7.5, 1);
        sprite.visible = this.labelsVisible && this.qualityLevel !== "low";

        sprite.userData = {
            dispose: () => {
                texture.dispose();
                material.dispose();
            },
        };

        return sprite;
    }

    renderStandardNodes(nodes) {
        nodes.forEach((nodeData) => {
            this.nodes.set(nodeData.id, nodeData);
            this.nodePositions.set(nodeData.id, new THREE.Vector3(
                Number(nodeData?.position?.x || 0),
                Number(nodeData?.position?.y || 0),
                Number(nodeData?.position?.z || 0),
            ));

            const geometry = this.getNodeGeometry(nodeData.type);
            const color = this.getNodeColor(nodeData);
            const material = new THREE.MeshPhongMaterial({
                color,
                emissive: color,
                emissiveIntensity: 0.18,
                shininess: 100,
                transparent: true,
                opacity: 1,
            });

            const mesh = new THREE.Mesh(geometry, material);
            mesh.position.copy(this.nodePositions.get(nodeData.id));
            mesh.userData = {
                nodeId: nodeData.id,
                nodeData,
                attackPulse: String(nodeData.status || "").toLowerCase() === "attacking",
            };

            const glowGeometry = this.getNodeGeometry(nodeData.type, 1.23);
            const glowMaterial = new THREE.MeshBasicMaterial({
                color,
                transparent: true,
                opacity: 0.16,
                blending: THREE.AdditiveBlending,
                depthWrite: false,
            });
            const glow = new THREE.Mesh(glowGeometry, glowMaterial);
            glow.name = "nodeGlow";
            mesh.add(glow);

            const label = this.createLabel(nodeData.label || nodeData.id);
            label.position.y = this.getNodeSize(nodeData.type) + 5;
            label.name = "nodeLabel";
            mesh.add(label);

            this.scene.add(mesh);
            this.nodeObjects.set(nodeData.id, mesh);
        });
    }

    createInstancedGroup(type, nodes) {
        const geometry = this.getNodeGeometry(type);
        const material = new THREE.MeshPhongMaterial({
            color: this.colors[type] || 0x888888,
            emissive: this.colors[type] || 0x888888,
            emissiveIntensity: 0.1,
            shininess: 80,
            transparent: true,
            opacity: 1,
            vertexColors: true,
        });

        const mesh = new THREE.InstancedMesh(geometry, material, nodes.length);
        mesh.instanceMatrix.setUsage(THREE.DynamicDrawUsage);

        const dummy = new THREE.Object3D();
        const color = new THREE.Color();

        nodes.forEach((nodeData, index) => {
            this.nodes.set(nodeData.id, nodeData);
            const pos = new THREE.Vector3(
                Number(nodeData?.position?.x || 0),
                Number(nodeData?.position?.y || 0),
                Number(nodeData?.position?.z || 0),
            );
            this.nodePositions.set(nodeData.id, pos);

            dummy.position.copy(pos);
            dummy.rotation.set(0, 0, 0);
            dummy.scale.set(1, 1, 1);
            dummy.updateMatrix();
            mesh.setMatrixAt(index, dummy.matrix);

            color.setHex(this.getNodeColor(nodeData));
            mesh.setColorAt(index, color);

            const key = `${type}:${index}`;
            this.instancedNodeLookup.set(key, nodeData.id);
            this.nodeObjects.set(nodeData.id, {
                instanced: true,
                type,
                index,
                nodeData,
            });
        });

        if (mesh.instanceColor) {
            mesh.instanceColor.needsUpdate = true;
        }
        mesh.userData = { instancedType: type };
        this.scene.add(mesh);
        this.instancedGroups.set(type, mesh);
        this.instancedPicker.push(mesh);
    }

    renderInstancedNodes(nodes) {
        const grouped = new Map();
        nodes.forEach((nodeData) => {
            const type = String(nodeData.type || "other");
            if (!grouped.has(type)) grouped.set(type, []);
            grouped.get(type).push(nodeData);
        });

        grouped.forEach((list, type) => {
            this.createInstancedGroup(type, list);
        });
    }

    createEdgeCurve(sourcePos, targetPos) {
        const midPoint = new THREE.Vector3().addVectors(sourcePos, targetPos).multiplyScalar(0.5);
        midPoint.z += 16;
        return new THREE.QuadraticBezierCurve3(sourcePos.clone(), midPoint, targetPos.clone());
    }

    addEdge(edgeData) {
        if (!edgeData || !edgeData.id) return;
        this.edges.set(edgeData.id, edgeData);

        const sourcePos = this.nodePositions.get(edgeData.source);
        const targetPos = this.nodePositions.get(edgeData.target);
        if (!sourcePos || !targetPos) return;

        const curve = this.createEdgeCurve(sourcePos, targetPos);
        this.edgeCurves.set(edgeData.id, curve);

        const points = curve.getPoints(24);
        const geometry = new THREE.BufferGeometry().setFromPoints(points);
        const material = new THREE.LineBasicMaterial({
            color: this.colors.edge[edgeData.type] || 0x4b5563,
            transparent: true,
            opacity: edgeData.animated ? 0.88 : 0.46,
            linewidth: 1,
        });

        const line = new THREE.Line(geometry, material);
        line.userData = { edgeId: edgeData.id, edgeData };
        this.scene.add(line);
        this.edgeObjects.set(edgeData.id, line);

        if (edgeData.animated) this.addEdgeParticles(edgeData.id, curve);
    }

    addEdgeParticles(edgeId, curve) {
        const particleCount = this.qualityLevel === "low" ? 6 : (this.qualityLevel === "medium" ? 12 : 20);
        const geometry = new THREE.BufferGeometry();
        const positions = new Float32Array(particleCount * 3);

        for (let i = 0; i < particleCount; i += 1) {
            const point = curve.getPoint(i / particleCount);
            positions[i * 3] = point.x;
            positions[(i * 3) + 1] = point.y;
            positions[(i * 3) + 2] = point.z;
        }

        geometry.setAttribute("position", new THREE.BufferAttribute(positions, 3));

        const material = new THREE.PointsMaterial({
            color: 0xff6666,
            size: this.qualityLevel === "low" ? 1.4 : 2.2,
            transparent: true,
            opacity: 0.8,
            depthWrite: false,
        });

        const points = new THREE.Points(geometry, material);
        points.userData = { edgeId, curve, progress: 0, speed: 0.25 };
        this.scene.add(points);
        this.particleSystems.set(edgeId, points);
    }

    updateParticles(deltaSeconds) {
        this.particleSystems.forEach((points) => {
            const state = points.userData;
            state.progress = (state.progress + (deltaSeconds * state.speed)) % 1;

            const attribute = points.geometry.getAttribute("position");
            const positions = attribute.array;
            const count = positions.length / 3;

            for (let i = 0; i < count; i += 1) {
                const t = (state.progress + (i / count)) % 1;
                const p = state.curve.getPoint(t);
                positions[i * 3] = p.x;
                positions[(i * 3) + 1] = p.y;
                positions[(i * 3) + 2] = p.z;
            }

            attribute.needsUpdate = true;
        });
    }

    updateNodeAnimation(elapsedMs) {
        const pulseTime = elapsedMs * 0.006;

        if (this.instancedMode) {
            const dummy = new THREE.Object3D();
            this.instancedGroups.forEach((mesh, type) => {
                const count = mesh.count;
                for (let i = 0; i < count; i += 1) {
                    const nodeId = this.instancedNodeLookup.get(`${type}:${i}`);
                    const nodeData = this.nodes.get(nodeId);
                    const pos = this.nodePositions.get(nodeId);
                    if (!nodeData || !pos) continue;

                    const pulse = String(nodeData.status || "").toLowerCase() === "attacking";
                    const scale = pulse ? (1 + (Math.sin(pulseTime) * 0.14)) : 1;

                    dummy.position.copy(pos);
                    dummy.rotation.set(0, elapsedMs * this.rotationSpeed * 0.001, 0);
                    dummy.scale.set(scale, scale, scale);
                    dummy.updateMatrix();
                    mesh.setMatrixAt(i, dummy.matrix);
                }
                mesh.instanceMatrix.needsUpdate = true;
            });
            return;
        }

        this.nodeObjects.forEach((mesh) => {
            if (!mesh || mesh.instanced) return;
            mesh.rotation.y += this.rotationSpeed;
            const shouldPulse = mesh.userData?.attackPulse;
            if (!shouldPulse) {
                mesh.scale.set(1, 1, 1);
                return;
            }
            const scale = 1 + (Math.sin(pulseTime) * 0.16);
            mesh.scale.set(scale, scale, scale);
        });
    }

    deriveGraphAdjacency() {
        const adjacency = new Map();
        this.nodes.forEach((_node, nodeId) => adjacency.set(nodeId, new Set()));

        this.edges.forEach((edge) => {
            if (!adjacency.has(edge.source)) adjacency.set(edge.source, new Set());
            if (!adjacency.has(edge.target)) adjacency.set(edge.target, new Set());
            adjacency.get(edge.source).add(edge.target);
            adjacency.get(edge.target).add(edge.source);
        });

        return adjacency;
    }

    shortestPath(sourceId, targetId) {
        if (!this.nodes.has(sourceId) || !this.nodes.has(targetId)) return [];
        if (sourceId === targetId) return [sourceId];

        const adjacency = this.deriveGraphAdjacency();
        const queue = [sourceId];
        const visited = new Set([sourceId]);
        const prev = new Map();

        while (queue.length) {
            const node = queue.shift();
            const neighbors = adjacency.get(node) || new Set();
            for (const next of neighbors) {
                if (visited.has(next)) continue;
                visited.add(next);
                prev.set(next, node);
                if (next === targetId) {
                    const path = [targetId];
                    let current = targetId;
                    while (prev.has(current)) {
                        current = prev.get(current);
                        path.unshift(current);
                    }
                    return path;
                }
                queue.push(next);
            }
        }

        return [];
    }

    setPathMode(enabled) {
        this.pathMode = Boolean(enabled);
        this.applyPathHighlight();
    }

    setPathEndpoints(sourceId, targetId) {
        this.pathSource = String(sourceId || "");
        this.pathTarget = String(targetId || "");
        this.applyPathHighlight();
    }

    applyStandardNodeColors(nodeSet) {
        this.nodeObjects.forEach((mesh, nodeId) => {
            if (mesh?.instanced) return;
            const highlighted = !nodeSet || nodeSet.has(nodeId);
            const nodeData = mesh.userData?.nodeData || this.nodes.get(nodeId) || {};
            mesh.material.opacity = highlighted ? 1 : 0.22;
            if (highlighted) {
                const color = nodeSet ? this.colors.highlight : this.getNodeColor(nodeData);
                mesh.material.color.setHex(color);
                mesh.material.emissive.setHex(color);
            } else {
                mesh.material.color.setHex(this.colors.mutedNode);
                mesh.material.emissive.setHex(this.colors.mutedNode);
            }
        });
    }

    applyInstancedNodeColors(nodeSet) {
        const color = new THREE.Color();
        this.instancedGroups.forEach((mesh, type) => {
            for (let i = 0; i < mesh.count; i += 1) {
                const nodeId = this.instancedNodeLookup.get(`${type}:${i}`);
                const nodeData = this.nodes.get(nodeId);
                const highlighted = !nodeSet || nodeSet.has(nodeId);
                if (highlighted) {
                    const colorValue = nodeSet ? this.colors.highlight : this.getNodeColor(nodeData);
                    color.setHex(colorValue);
                } else {
                    color.setHex(this.colors.mutedNode);
                }
                mesh.setColorAt(i, color);
            }
            if (mesh.instanceColor) {
                mesh.instanceColor.needsUpdate = true;
            }
        });
    }

    applyPathHighlight() {
        if (!this.pathMode) {
            this.applyStandardNodeColors(null);
            if (this.instancedMode) this.applyInstancedNodeColors(null);
            this.edgeObjects.forEach((line) => {
                const edgeData = line.userData?.edgeData || {};
                line.material.opacity = edgeData.animated ? 0.88 : 0.46;
                line.material.color.setHex(this.colors.edge[edgeData.type] || 0x4b5563);
            });
            this.setBloomIntensity(0.55);
            return;
        }

        const path = this.shortestPath(this.pathSource, this.pathTarget);
        const nodeSet = new Set(path);
        const edgeSet = new Set();

        for (let i = 0; i < path.length - 1; i += 1) {
            const a = path[i];
            const b = path[i + 1];
            this.edges.forEach((edge, edgeId) => {
                if ((edge.source === a && edge.target === b) || (edge.source === b && edge.target === a)) {
                    edgeSet.add(edgeId);
                }
            });
        }

        this.applyStandardNodeColors(nodeSet);
        if (this.instancedMode) this.applyInstancedNodeColors(nodeSet);

        let criticalHits = 0;
        this.edgeObjects.forEach((line, edgeId) => {
            const highlighted = edgeSet.has(edgeId);
            line.material.opacity = highlighted ? 0.95 : 0.12;
            line.material.color.setHex(highlighted ? this.colors.highlight : this.colors.mutedEdge);
            if (highlighted) {
                const edge = this.edges.get(edgeId) || {};
                const source = this.nodes.get(edge.source) || {};
                const target = this.nodes.get(edge.target) || {};
                if ([source.severity, target.severity].some((s) => String(s || "").toLowerCase() === "critical")) {
                    criticalHits += 1;
                }
            }
        });

        this.setBloomIntensity(0.7 + Math.min(0.6, criticalHits * 0.08));
    }

    setCameraPreset(preset) {
        const map = {
            global: { position: new THREE.Vector3(0, -180, 170), target: new THREE.Vector3(0, 0, 40) },
            lateral: { position: new THREE.Vector3(230, 0, 70), target: new THREE.Vector3(0, 0, 55) },
            overhead: { position: new THREE.Vector3(0, 0, 340), target: new THREE.Vector3(0, 0, 50) },
            incident: { position: new THREE.Vector3(80, -100, 120), target: new THREE.Vector3(0, 0, 60) },
        };
        const selected = map[preset] || map.global;
        this.animateCameraTo(selected.position, selected.target, 700);
    }

    animateCameraTo(position, target, durationMs = 1000) {
        const startPosition = this.camera.position.clone();
        const startTarget = this.controls.target.clone();
        const startedAt = performance.now();

        const tick = () => {
            const elapsed = performance.now() - startedAt;
            const progress = Math.min(elapsed / durationMs, 1);
            const eased = 1 - Math.pow(1 - progress, 3);

            this.camera.position.lerpVectors(startPosition, position, eased);
            this.controls.target.lerpVectors(startTarget, target, eased);

            if (progress < 1) requestAnimationFrame(tick);
        };

        tick();
    }

    focusOnNode(nodeId) {
        const pos = this.nodePositions.get(nodeId);
        if (!pos) return;

        const position = pos.clone().add(new THREE.Vector3(18, -26, 42));
        this.animateCameraTo(position, pos.clone(), 900);
    }

    setLabelVisibility(visible) {
        this.labelsVisible = Boolean(visible);
        this.nodeObjects.forEach((mesh) => {
            if (!mesh || mesh.instanced) return;
            const label = mesh.getObjectByName("nodeLabel");
            if (label) label.visible = this.labelsVisible;
        });
    }

    setQualityLevel(level) {
        const normalized = ["low", "medium", "high"].includes(level) ? level : "high";
        if (this.qualityLevel === normalized) return;

        this.qualityLevel = normalized;
        this.rotationSpeed = normalized === "low" ? 0.0008 : (normalized === "medium" ? 0.0014 : 0.002);
        this.setLabelVisibility(normalized !== "low");

        this.particleSystems.forEach((points) => {
            this.disposeObject(points);
            this.scene.remove(points);
        });
        this.particleSystems.clear();

        this.edges.forEach((edge, edgeId) => {
            if (edge.animated) {
                const curve = this.edgeCurves.get(edgeId);
                if (curve) this.addEdgeParticles(edgeId, curve);
            }
        });

        this.container.dispatchEvent(new CustomEvent("qualityChange", {
            detail: { level: this.qualityLevel },
        }));
    }

    updateAdaptiveQuality(fps) {
        this.fpsSamples.push(fps);
        if (this.fpsSamples.length > 40) this.fpsSamples.shift();
        const avg = this.fpsSamples.reduce((a, b) => a + b, 0) / this.fpsSamples.length;

        if (avg < 28 && this.qualityLevel !== "low") {
            this.setQualityLevel(this.qualityLevel === "high" ? "medium" : "low");
        }
        if (avg > 52 && this.qualityLevel !== "high") {
            this.setQualityLevel(this.qualityLevel === "low" ? "medium" : "high");
        }
    }

    onResize() {
        const width = this.container.clientWidth;
        const height = this.container.clientHeight;
        this.camera.aspect = width / height;
        this.camera.updateProjectionMatrix();
        this.renderer.setSize(width, height);
        if (this.composer) this.composer.setSize(width, height);
    }

    onMouseMove(event) {
        const rect = this.renderer.domElement.getBoundingClientRect();
        this.mouse.x = ((event.clientX - rect.left) / rect.width) * 2 - 1;
        this.mouse.y = -((event.clientY - rect.top) / rect.height) * 2 + 1;

        this.raycaster.setFromCamera(this.mouse, this.camera);

        if (this.instancedMode) {
            const intersects = this.raycaster.intersectObjects(this.instancedPicker, false);
            if (!intersects.length) {
                this.hoveredNode = null;
                this.container.style.cursor = "default";
                return;
            }
            const hit = intersects[0];
            const type = hit.object?.userData?.instancedType;
            const instanceId = hit.instanceId;
            const nodeId = this.instancedNodeLookup.get(`${type}:${instanceId}`);
            this.hoveredNode = nodeId || null;
            this.container.style.cursor = nodeId ? "pointer" : "default";
            return;
        }

        const meshes = Array.from(this.nodeObjects.values()).filter((m) => m && !m.instanced);
        const intersects = this.raycaster.intersectObjects(meshes);

        if (intersects.length > 0) {
            const mesh = intersects[0].object;
            if (this.hoveredNode !== mesh) {
                if (this.hoveredNode && this.hoveredNode.scale) this.hoveredNode.scale.set(1, 1, 1);
                this.hoveredNode = mesh;
                mesh.scale.set(1.2, 1.2, 1.2);
                this.container.style.cursor = "pointer";
            }
        } else {
            if (this.hoveredNode && this.hoveredNode.scale) this.hoveredNode.scale.set(1, 1, 1);
            this.hoveredNode = null;
            this.container.style.cursor = "default";
        }
    }

    onClick() {
        if (!this.hoveredNode) return;

        let nodeData;
        if (this.instancedMode) {
            const nodeId = this.hoveredNode;
            nodeData = this.nodes.get(nodeId);
        } else {
            nodeData = this.hoveredNode.userData?.nodeData;
        }
        if (!nodeData) return;

        this.selectedNode = nodeData;
        this.focusOnNode(nodeData.id);

        this.container.dispatchEvent(new CustomEvent("nodeClick", {
            detail: nodeData,
        }));
    }

    clearNodesAndEdges() {
        this.nodeObjects.forEach((mesh) => {
            if (mesh?.instanced) return;
            this.scene.remove(mesh);
            this.disposeObject(mesh);
        });
        this.edgeObjects.forEach((line) => {
            this.scene.remove(line);
            this.disposeObject(line);
        });
        this.particleSystems.forEach((points) => {
            this.scene.remove(points);
            this.disposeObject(points);
        });

        this.instancedGroups.forEach((mesh) => {
            this.scene.remove(mesh);
            this.disposeObject(mesh);
        });

        this.nodes.clear();
        this.edges.clear();
        this.nodeObjects.clear();
        this.edgeObjects.clear();
        this.edgeCurves.clear();
        this.particleSystems.clear();
        this.nodePositions.clear();
        this.instancedGroups.clear();
        this.instancedNodeLookup.clear();
        this.instancedPicker = [];
        this.hoveredNode = null;
    }

    updateFromState(state) {
        const layoutState = this.generateDeterministicLayout(state || { nodes: [], edges: [] });

        this.clearNodesAndEdges();
        this.instancedMode = (layoutState.nodes || []).length >= this.instancedThreshold;

        if (this.instancedMode) {
            this.renderInstancedNodes(layoutState.nodes || []);
        } else {
            this.renderStandardNodes(layoutState.nodes || []);
            this.setLabelVisibility(this.labelsVisible);
        }

        (layoutState.edges || []).forEach((edge) => this.addEdge(edge));
        this.applyPathHighlight();

        this.container.dispatchEvent(new CustomEvent("instancedMode", {
            detail: { enabled: this.instancedMode, count: (layoutState.nodes || []).length },
        }));
    }

    disposeObject(object) {
        if (!object) return;

        object.traverse?.((child) => {
            if (child.geometry) child.geometry.dispose?.();

            if (child.material) {
                if (Array.isArray(child.material)) {
                    child.material.forEach((mat) => mat.dispose?.());
                } else {
                    child.material.dispose?.();
                }
            }

            if (child.userData?.dispose && typeof child.userData.dispose === "function") {
                child.userData.dispose();
            }
        });
    }

    clear() {
        this.clearNodesAndEdges();
    }

    getGraphState() {
        return {
            nodes: Array.from(this.nodes.values()),
            edges: Array.from(this.edges.values()),
        };
    }

    captureCanvasDataUrl() {
        try {
            return this.renderer?.domElement?.toDataURL("image/png") || "";
        } catch (_error) {
            return "";
        }
    }

    animate() {
        this.animationHandle = requestAnimationFrame(() => this.animate());

        const now = performance.now();
        const delta = Math.max(0.001, (now - this.lastFrameTime) / 1000);
        this.lastFrameTime = now;

        const fps = 1 / delta;
        this.updateAdaptiveQuality(fps);

        this.controls.update();
        this.updateParticles(delta);
        this.updateNodeAnimation(now);

        if (this.composer) {
            this.composer.render();
        } else {
            this.renderer.render(this.scene, this.camera);
        }
    }

    destroy() {
        if (this.animationHandle) cancelAnimationFrame(this.animationHandle);
        this.clear();
        this.geometryCache.forEach((geometry) => geometry.dispose?.());
        this.geometryCache.clear();
        this.renderer.dispose();
        this.container.innerHTML = "";
    }
}


class MetricsDashboard {
    constructor(containerId) {
        this.container = document.getElementById(containerId);
        this.init();
    }

    init() {
        if (!this.container) return;
        this.container.innerHTML = `
            <div class="metrics-grid">
                <div class="metric-card wide">
                    <div class="metric-label">Overall Progress</div>
                    <div class="metric-value" id="metric-progress">0%</div>
                    <div class="progress-bar"><div class="progress-fill" id="progress-fill"></div></div>
                </div>
                <div class="metric-card">
                    <div class="metric-label">Vulnerabilities</div>
                    <div class="metric-value" id="metric-vulns">0</div>
                </div>
                <div class="metric-card">
                    <div class="metric-label">Exploits</div>
                    <div class="metric-value" id="metric-exploits">0/0</div>
                </div>
                <div class="metric-card">
                    <div class="metric-label">Hosts</div>
                    <div class="metric-value" id="metric-hosts">0</div>
                </div>
                <div class="metric-card">
                    <div class="metric-label">Agents</div>
                    <div class="metric-value" id="metric-agents">0</div>
                </div>
            </div>
        `;
    }

    update(metrics) {
        const progress = Math.round(Number(metrics?.attack_progress || 0));
        const vulns = Number(metrics?.vulnerabilities_found || 0);
        const successes = Number(metrics?.exploits_successful || 0);
        const attempts = Number(metrics?.exploits_attempted || 0);
        const hosts = Number(metrics?.hosts_scanned || 0);
        const agents = Number(metrics?.agents_active || 0);

        const progressEl = document.getElementById("metric-progress");
        const progressFillEl = document.getElementById("progress-fill");
        const vulnsEl = document.getElementById("metric-vulns");
        const exploitsEl = document.getElementById("metric-exploits");
        const hostsEl = document.getElementById("metric-hosts");
        const agentsEl = document.getElementById("metric-agents");

        if (progressEl) progressEl.textContent = `${progress}%`;
        if (progressFillEl) progressFillEl.style.width = `${progress}%`;
        if (vulnsEl) vulnsEl.textContent = String(vulns);
        if (exploitsEl) exploitsEl.textContent = `${successes}/${attempts}`;
        if (hostsEl) hostsEl.textContent = String(hosts);
        if (agentsEl) agentsEl.textContent = String(agents);
    }
}


class VisualizationConnection {
    constructor(url, visualization, dashboard) {
        this.url = url;
        this.visualization = visualization;
        this.dashboard = dashboard;
        this.ws = null;
        this.reconnectAttempts = 0;
        this.maxReconnectAttempts = 5;
    }

    connect() {
        try {
            this.ws = new WebSocket(this.url);

            this.ws.onopen = () => {
                console.log("Visualization WebSocket connected");
                this.reconnectAttempts = 0;
            };

            this.ws.onmessage = (event) => {
                const data = JSON.parse(event.data);
                this.handleMessage(data);
            };

            this.ws.onclose = () => {
                console.log("Visualization WebSocket disconnected");
                this.scheduleReconnect();
            };

            this.ws.onerror = (error) => {
                console.error("WebSocket error:", error);
            };
        } catch (error) {
            console.error("Failed to connect:", error);
            this.scheduleReconnect();
        }
    }

    scheduleReconnect() {
        if (this.reconnectAttempts >= this.maxReconnectAttempts) return;
        this.reconnectAttempts += 1;
        const delay = Math.min(1000 * (2 ** this.reconnectAttempts), 30000);
        setTimeout(() => this.connect(), delay);
    }

    handleMessage(data) {
        switch (data.type) {
            case "initial_state":
                this.visualization.updateFromState(data.graph);
                this.dashboard.update(data.metrics);
                break;
            case "metrics_update":
                this.dashboard.update(data.metrics);
                break;
            case "host_discovered":
            case "port_discovered":
            case "vuln_detected":
            case "attack_success":
                if (data.graph) this.visualization.updateFromState(data.graph);
                break;
            default:
                break;
        }
    }

    disconnect() {
        if (this.ws) this.ws.close();
    }
}


if (typeof module !== "undefined" && module.exports) {
    module.exports = { AttackVisualization, MetricsDashboard, VisualizationConnection };
}
