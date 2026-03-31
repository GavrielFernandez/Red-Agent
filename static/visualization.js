/**
 * RedAgent 3D Attack Visualization
 * =================================
 * 
 * Real-time 3D attack graph visualization using Three.js
 * Features: 3D nodes, animated connections, live updates
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
        
        this.scene = null;
        this.camera = null;
        this.renderer = null;
        this.controls = null;
        this.raycaster = null;
        this.mouse = null;
        
        this.selectedNode = null;
        this.hoveredNode = null;
        
        this.colors = {
            target: 0x4a90d9,
            host: 0x50c878,
            service: 0xffd700,
            vulnerability: 0xff6b6b,
            exploit: 0x8b0000,
            data: 0x9370db,
            
            edge: {
                discovered: 0x555555,
                attacking: 0xff4444,
                exploited: 0x8b0000
            },
            
            severity: {
                critical: 0xff0000,
                high: 0xff6600,
                medium: 0xffcc00,
                low: 0x00cc00,
                info: 0x0099ff
            }
        };
        
        this.init();
    }
    
    init() {
        // Scene setup
        this.scene = new THREE.Scene();
        this.scene.background = new THREE.Color(0x0a0a0f);
        this.scene.fog = new THREE.Fog(0x0a0a0f, 100, 500);
        
        // Camera
        const aspect = this.container.clientWidth / this.container.clientHeight;
        this.camera = new THREE.PerspectiveCamera(75, aspect, 0.1, 1000);
        this.camera.position.set(0, 0, 150);
        
        // Renderer
        this.renderer = new THREE.WebGLRenderer({ 
            antialias: true,
            alpha: true 
        });
        this.renderer.setSize(this.container.clientWidth, this.container.clientHeight);
        this.renderer.setPixelRatio(window.devicePixelRatio);
        this.container.appendChild(this.renderer.domElement);
        
        // Controls
        this.controls = new THREE.OrbitControls(this.camera, this.renderer.domElement);
        this.controls.enableDamping = true;
        this.controls.dampingFactor = 0.05;
        this.controls.screenSpacePanning = true;
        this.controls.minDistance = 50;
        this.controls.maxDistance = 500;
        
        // Raycaster for interaction
        this.raycaster = new THREE.Raycaster();
        this.mouse = new THREE.Vector2();
        
        // Lighting
        this.setupLighting();
        
        // Grid helper
        const grid = new THREE.GridHelper(200, 20, 0x222222, 0x111111);
        grid.rotation.x = Math.PI / 2;
        this.scene.add(grid);
        
        // Event listeners
        window.addEventListener('resize', () => this.onResize());
        this.renderer.domElement.addEventListener('mousemove', (e) => this.onMouseMove(e));
        this.renderer.domElement.addEventListener('click', (e) => this.onClick(e));
        
        // Start animation loop
        this.animate();
    }
    
    setupLighting() {
        // Ambient light
        const ambient = new THREE.AmbientLight(0x404040, 0.5);
        this.scene.add(ambient);
        
        // Directional lights
        const light1 = new THREE.DirectionalLight(0xffffff, 0.8);
        light1.position.set(100, 100, 100);
        this.scene.add(light1);
        
        const light2 = new THREE.DirectionalLight(0x4a90d9, 0.3);
        light2.position.set(-100, -100, -100);
        this.scene.add(light2);
        
        // Point lights for dramatic effect
        const point1 = new THREE.PointLight(0xff0000, 0.5, 200);
        point1.position.set(50, 50, 50);
        this.scene.add(point1);
        
        const point2 = new THREE.PointLight(0x00ff00, 0.3, 200);
        point2.position.set(-50, -50, -50);
        this.scene.add(point2);
    }
    
    addNode(nodeData) {
        if (this.nodes.has(nodeData.id)) {
            this.updateNode(nodeData);
            return;
        }
        
        this.nodes.set(nodeData.id, nodeData);
        
        // Create 3D object
        const geometry = this.getNodeGeometry(nodeData.type);
        const material = new THREE.MeshPhongMaterial({
            color: this.getNodeColor(nodeData),
            emissive: this.getNodeColor(nodeData),
            emissiveIntensity: 0.2,
            shininess: 100
        });
        
        const mesh = new THREE.Mesh(geometry, material);
        mesh.position.set(
            nodeData.position.x || 0,
            nodeData.position.y || 0,
            nodeData.position.z || 0
        );
        mesh.userData = { nodeId: nodeData.id, nodeData };
        
        // Add glow effect
        const glowGeometry = this.getNodeGeometry(nodeData.type, 1.2);
        const glowMaterial = new THREE.MeshBasicMaterial({
            color: this.getNodeColor(nodeData),
            transparent: true,
            opacity: 0.2
        });
        const glow = new THREE.Mesh(glowGeometry, glowMaterial);
        mesh.add(glow);
        
        // Add label
        const label = this.createLabel(nodeData.label);
        label.position.y = this.getNodeSize(nodeData.type) + 5;
        mesh.add(label);
        
        this.scene.add(mesh);
        this.nodeObjects.set(nodeData.id, mesh);
    }
    
    updateNode(nodeData) {
        const existingData = this.nodes.get(nodeData.id);
        if (!existingData) return;
        
        Object.assign(existingData, nodeData);
        
        const mesh = this.nodeObjects.get(nodeData.id);
        if (mesh) {
            mesh.material.color.setHex(this.getNodeColor(nodeData));
            mesh.material.emissive.setHex(this.getNodeColor(nodeData));
            
            // Pulse animation for attacking status
            if (nodeData.status === 'attacking') {
                this.pulseNode(mesh);
            }
        }
    }
    
    addEdge(edgeData) {
        if (this.edges.has(edgeData.id)) {
            this.updateEdge(edgeData);
            return;
        }
        
        this.edges.set(edgeData.id, edgeData);
        
        const sourceNode = this.nodeObjects.get(edgeData.source);
        const targetNode = this.nodeObjects.get(edgeData.target);
        
        if (!sourceNode || !targetNode) return;
        
        // Create curved line
        const sourcePos = sourceNode.position;
        const targetPos = targetNode.position;
        
        const midPoint = new THREE.Vector3()
            .addVectors(sourcePos, targetPos)
            .multiplyScalar(0.5);
        midPoint.z += 20; // Curve upward
        
        const curve = new THREE.QuadraticBezierCurve3(
            sourcePos.clone(),
            midPoint,
            targetPos.clone()
        );
        
        const geometry = new THREE.TubeGeometry(curve, 32, 0.5, 8, false);
        const material = new THREE.MeshBasicMaterial({
            color: this.colors.edge[edgeData.type] || 0x555555,
            transparent: true,
            opacity: edgeData.animated ? 0.8 : 0.5
        });
        
        const mesh = new THREE.Mesh(geometry, material);
        mesh.userData = { edgeId: edgeData.id, edgeData };
        
        this.scene.add(mesh);
        this.edgeObjects.set(edgeData.id, mesh);
        
        // Add animated particles for active attacks
        if (edgeData.animated) {
            this.addEdgeParticles(edgeData.id, curve);
        }
    }
    
    updateEdge(edgeData) {
        const mesh = this.edgeObjects.get(edgeData.id);
        if (mesh) {
            mesh.material.color.setHex(this.colors.edge[edgeData.type] || 0x555555);
        }
    }
    
    addEdgeParticles(edgeId, curve) {
        const particleCount = 20;
        const geometry = new THREE.BufferGeometry();
        const positions = new Float32Array(particleCount * 3);
        
        for (let i = 0; i < particleCount; i++) {
            const point = curve.getPoint(i / particleCount);
            positions[i * 3] = point.x;
            positions[i * 3 + 1] = point.y;
            positions[i * 3 + 2] = point.z;
        }
        
        geometry.setAttribute('position', new THREE.BufferAttribute(positions, 3));
        
        const material = new THREE.PointsMaterial({
            color: 0xff4444,
            size: 2,
            transparent: true,
            opacity: 0.8
        });
        
        const particles = new THREE.Points(geometry, material);
        particles.userData = { edgeId, curve, progress: 0 };
        
        this.scene.add(particles);
        this.animateParticles(particles);
    }
    
    animateParticles(particles) {
        const animate = () => {
            if (!particles.parent) return;
            
            particles.userData.progress += 0.02;
            if (particles.userData.progress > 1) {
                particles.userData.progress = 0;
            }
            
            const positions = particles.geometry.attributes.position.array;
            const count = positions.length / 3;
            const curve = particles.userData.curve;
            
            for (let i = 0; i < count; i++) {
                const t = (particles.userData.progress + i / count) % 1;
                const point = curve.getPoint(t);
                positions[i * 3] = point.x;
                positions[i * 3 + 1] = point.y;
                positions[i * 3 + 2] = point.z;
            }
            
            particles.geometry.attributes.position.needsUpdate = true;
            requestAnimationFrame(animate);
        };
        
        animate();
    }
    
    getNodeGeometry(type, scale = 1) {
        const size = this.getNodeSize(type) * scale;
        
        switch (type) {
            case 'target':
                return new THREE.OctahedronGeometry(size);
            case 'host':
                return new THREE.BoxGeometry(size, size, size);
            case 'service':
                return new THREE.CylinderGeometry(size * 0.7, size, size, 6);
            case 'vulnerability':
                return new THREE.TetrahedronGeometry(size);
            case 'exploit':
                return new THREE.IcosahedronGeometry(size);
            case 'data':
                return new THREE.TorusGeometry(size * 0.7, size * 0.3, 8, 16);
            default:
                return new THREE.SphereGeometry(size);
        }
    }
    
    getNodeSize(type) {
        const sizes = {
            target: 8,
            host: 6,
            service: 4,
            vulnerability: 5,
            exploit: 7,
            data: 4
        };
        return sizes[type] || 5;
    }
    
    getNodeColor(nodeData) {
        // Priority: severity -> type
        if (nodeData.severity && nodeData.severity !== 'info') {
            return this.colors.severity[nodeData.severity] || this.colors[nodeData.type];
        }
        return this.colors[nodeData.type] || 0x888888;
    }
    
    createLabel(text) {
        const canvas = document.createElement('canvas');
        const context = canvas.getContext('2d');
        canvas.width = 256;
        canvas.height = 64;
        
        context.fillStyle = 'rgba(0, 0, 0, 0.7)';
        context.fillRect(0, 0, canvas.width, canvas.height);
        
        context.font = 'bold 24px Arial';
        context.fillStyle = '#ffffff';
        context.textAlign = 'center';
        context.fillText(text.substring(0, 20), canvas.width / 2, canvas.height / 2 + 8);
        
        const texture = new THREE.CanvasTexture(canvas);
        const material = new THREE.SpriteMaterial({ 
            map: texture, 
            transparent: true 
        });
        const sprite = new THREE.Sprite(material);
        sprite.scale.set(30, 7.5, 1);
        
        return sprite;
    }
    
    pulseNode(mesh) {
        const originalScale = mesh.scale.x;
        const pulse = () => {
            const time = Date.now() * 0.005;
            const scale = originalScale + Math.sin(time) * 0.2;
            mesh.scale.set(scale, scale, scale);
        };
        
        mesh.userData.pulseInterval = setInterval(pulse, 50);
    }
    
    onResize() {
        const width = this.container.clientWidth;
        const height = this.container.clientHeight;
        
        this.camera.aspect = width / height;
        this.camera.updateProjectionMatrix();
        this.renderer.setSize(width, height);
    }
    
    onMouseMove(event) {
        const rect = this.renderer.domElement.getBoundingClientRect();
        this.mouse.x = ((event.clientX - rect.left) / rect.width) * 2 - 1;
        this.mouse.y = -((event.clientY - rect.top) / rect.height) * 2 + 1;
        
        this.raycaster.setFromCamera(this.mouse, this.camera);
        
        const meshes = Array.from(this.nodeObjects.values());
        const intersects = this.raycaster.intersectObjects(meshes);
        
        if (intersects.length > 0) {
            const object = intersects[0].object;
            if (this.hoveredNode !== object) {
                if (this.hoveredNode) {
                    this.hoveredNode.scale.set(1, 1, 1);
                }
                this.hoveredNode = object;
                object.scale.set(1.3, 1.3, 1.3);
                this.container.style.cursor = 'pointer';
            }
        } else {
            if (this.hoveredNode) {
                this.hoveredNode.scale.set(1, 1, 1);
                this.hoveredNode = null;
            }
            this.container.style.cursor = 'default';
        }
    }
    
    onClick(event) {
        if (this.hoveredNode) {
            const nodeData = this.hoveredNode.userData.nodeData;
            this.selectedNode = nodeData;
            this.focusOnNode(nodeData.id);
            
            // Dispatch custom event
            this.container.dispatchEvent(new CustomEvent('nodeClick', {
                detail: nodeData
            }));
        }
    }
    
    focusOnNode(nodeId) {
        const mesh = this.nodeObjects.get(nodeId);
        if (!mesh) return;
        
        const targetPos = mesh.position.clone();
        targetPos.z += 50;
        
        // Animate camera
        const startPos = this.camera.position.clone();
        const duration = 1000;
        const startTime = Date.now();
        
        const animateCamera = () => {
            const elapsed = Date.now() - startTime;
            const progress = Math.min(elapsed / duration, 1);
            const eased = 1 - Math.pow(1 - progress, 3);
            
            this.camera.position.lerpVectors(startPos, targetPos, eased);
            this.controls.target.lerp(mesh.position, eased);
            
            if (progress < 1) {
                requestAnimationFrame(animateCamera);
            }
        };
        
        animateCamera();
    }
    
    updateFromState(state) {
        // Update nodes
        if (state.nodes) {
            state.nodes.forEach(node => this.addNode(node));
        }
        
        // Update edges
        if (state.edges) {
            state.edges.forEach(edge => this.addEdge(edge));
        }
    }
    
    clear() {
        this.nodeObjects.forEach((mesh, id) => {
            this.scene.remove(mesh);
        });
        this.edgeObjects.forEach((mesh, id) => {
            this.scene.remove(mesh);
        });
        
        this.nodes.clear();
        this.edges.clear();
        this.nodeObjects.clear();
        this.edgeObjects.clear();
    }
    
    animate() {
        requestAnimationFrame(() => this.animate());
        
        this.controls.update();
        
        // Rotate nodes slightly
        this.nodeObjects.forEach((mesh) => {
            mesh.rotation.y += 0.002;
        });
        
        this.renderer.render(this.scene, this.camera);
    }
}


/**
 * Real-time Metrics Dashboard
 */
class MetricsDashboard {
    constructor(containerId) {
        this.container = document.getElementById(containerId);
        this.charts = {};
        this.init();
    }
    
    init() {
        this.container.innerHTML = `
            <div class="metrics-grid">
                <div class="metric-card">
                    <div class="metric-label">Progress</div>
                    <div class="metric-value" id="metric-progress">0%</div>
                    <div class="progress-bar">
                        <div class="progress-fill" id="progress-fill"></div>
                    </div>
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
                    <div class="metric-label">Active Agents</div>
                    <div class="metric-value" id="metric-agents">0</div>
                </div>
                <div class="metric-card wide">
                    <div class="metric-label">Findings by Severity</div>
                    <canvas id="severity-chart"></canvas>
                </div>
                <div class="metric-card wide">
                    <div class="metric-label">Attack Vectors</div>
                    <canvas id="vectors-chart"></canvas>
                </div>
            </div>
        `;
    }
    
    update(metrics) {
        // Update simple metrics
        document.getElementById('metric-progress').textContent = 
            `${Math.round(metrics.attack_progress)}%`;
        document.getElementById('progress-fill').style.width = 
            `${metrics.attack_progress}%`;
        document.getElementById('metric-vulns').textContent = 
            metrics.vulnerabilities_found;
        document.getElementById('metric-exploits').textContent = 
            `${metrics.exploits_successful}/${metrics.exploits_attempted}`;
        document.getElementById('metric-agents').textContent = 
            metrics.agents_active;
    }
}


/**
 * WebSocket Connection Manager
 */
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
                console.log('Visualization WebSocket connected');
                this.reconnectAttempts = 0;
            };
            
            this.ws.onmessage = (event) => {
                const data = JSON.parse(event.data);
                this.handleMessage(data);
            };
            
            this.ws.onclose = () => {
                console.log('Visualization WebSocket disconnected');
                this.scheduleReconnect();
            };
            
            this.ws.onerror = (error) => {
                console.error('WebSocket error:', error);
            };
        } catch (error) {
            console.error('Failed to connect:', error);
            this.scheduleReconnect();
        }
    }
    
    scheduleReconnect() {
        if (this.reconnectAttempts < this.maxReconnectAttempts) {
            this.reconnectAttempts++;
            const delay = Math.min(1000 * Math.pow(2, this.reconnectAttempts), 30000);
            console.log(`Reconnecting in ${delay}ms...`);
            setTimeout(() => this.connect(), delay);
        }
    }
    
    handleMessage(data) {
        switch (data.type) {
            case 'initial_state':
                this.visualization.updateFromState(data.graph);
                this.dashboard.update(data.metrics);
                break;
            
            case 'metrics_update':
                this.dashboard.update(data.metrics);
                break;
            
            case 'host_discovered':
            case 'port_discovered':
            case 'vuln_detected':
            case 'attack_success':
                // Graph updates handled by visualization
                if (data.graph) {
                    this.visualization.updateFromState(data.graph);
                }
                break;
        }
    }
    
    disconnect() {
        if (this.ws) {
            this.ws.close();
        }
    }
}


// Export for use
if (typeof module !== 'undefined' && module.exports) {
    module.exports = { AttackVisualization, MetricsDashboard, VisualizationConnection };
}
