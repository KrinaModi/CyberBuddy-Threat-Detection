/*!
 * CyberBuddy Geo Intelligence Canvas Engine
 * ==========================================
 * Version   : 1.0.0
 * Author    : CyberBuddy Frontend Team
 * Purpose   : Reusable, API-ready world-map threat visualization
 *             designed for SOC (Security Operations Center) dashboards.
 *
 * Architecture:
 *   - Pure vanilla JavaScript — zero external dependencies
 *   - Equirectangular geographic projection (lat/lon → pixel)
 *   - Offscreen canvas for static layers (continent dots + grid) — rendered once
 *   - Animated layer for geo nodes, arc connections, and data packets — 60fps
 *   - Full public API surface for future backend threat-intelligence integration
 *
 * ─────────────────────────────────────────────────────────────────────────────
 * PUBLIC API
 * ─────────────────────────────────────────────────────────────────────────────
 *
 *   CyberBuddyMap.init(canvasId, options?)
 *     Initialize on a <canvas> element.
 *     options.maxArcs   {number}  Max simultaneous connection arcs (default 5)
 *     options.arcSpeed  {number}  Data-packet travel speed 0.1–2.0 (default 0.7)
 *     options.nodeSize  {number}  Base radius for geo nodes in px (default 3)
 *
 *   CyberBuddyMap.setNodes(nodeArray)
 *     Replace demo nodes with backend-provided geographic data.
 *     node: { lat, lon, id, severity? }
 *     severity: 'low' | 'medium' | 'high' | 'critical'
 *
 *   CyberBuddyMap.addThreat(threat)
 *     Fire a single threat-connection arc from a backend event.
 *     threat: { srcLat, srcLon, dstLat, dstLon, severity?, type?, timestamp? }
 *     severity: 'low' | 'medium' | 'high' | 'critical'
 *
 *   CyberBuddyMap.clearThreats()
 *     Remove all active threat arcs immediately.
 *
 *   CyberBuddyMap.destroy()
 *     Stop animation loop and release all resources.
 *
 * ─────────────────────────────────────────────────────────────────────────────
 * USAGE
 * ─────────────────────────────────────────────────────────────────────────────
 *   <canvas id="cyber-canvas"></canvas>
 *   <script src="/static/cyber-canvas.js"></script>
 *   <script>
 *     document.addEventListener('DOMContentLoaded', function () {
 *       CyberBuddyMap.init('cyber-canvas');
 *     });
 *   </script>
 * ─────────────────────────────────────────────────────────────────────────────
 */

(function (global) {
    'use strict';

    // ─────────────────────────────────────────────────────────────────────────
    // CONFIGURATION DEFAULTS
    // ─────────────────────────────────────────────────────────────────────────

    var DEFAULTS = {
        maxArcs:   5,
        arcSpeed:  0.7,
        nodeSize:  3,
    };

    // ─────────────────────────────────────────────────────────────────────────
    // COLOR PALETTE
    // Uses rgba string prefixes for fast opacity composition.
    // ─────────────────────────────────────────────────────────────────────────

    var C = {
        CYAN:    'rgba(6,182,212,',
        BLUE:    'rgba(59,130,246,',
        EMERALD: 'rgba(16,185,129,',
        AMBER:   'rgba(245,158,11,',
        ORANGE:  'rgba(249,115,22,',
        ROSE:    'rgba(244,63,94,',
        WHITE:   'rgba(248,250,252,',
    };

    // Maps severity labels to their canvas color prefix
    var SEVERITY_COL = {
        low:      C.EMERALD,
        medium:   C.AMBER,
        high:     C.ORANGE,
        critical: C.ROSE,
    };

    // ─────────────────────────────────────────────────────────────────────────
    // WORLD MAP — DOT-MATRIX GEOGRAPHIC DATA
    //
    // Each entry is [latitude, longitude] in decimal degrees.
    // These points define the world's major land masses when rendered as a
    // dot-matrix visualization. No city names or country identifiers are stored;
    // the data is purely geographic coordinate pairs.
    //
    // When the backend API is integrated, real threat-event coordinates will
    // overlay this static base using CyberBuddyMap.addThreat().
    // ─────────────────────────────────────────────────────────────────────────

    var WORLD_DOTS = [
        // ── North America: Alaska ──────────────────────────────────────────
        [65,-168],[65,-156],[65,-146],[60,-152],[60,-142],[57,-136],[55,-131],
        // ── North America: Canada ─────────────────────────────────────────
        [70,-130],[70,-120],[70,-110],[70,-100],[70,-90],[70,-82],
        [65,-128],[65,-118],[65,-106],[65,-96],[65,-82],[65,-70],
        [60,-140],[60,-126],[60,-116],[60,-100],[60,-88],[60,-75],[60,-66],
        [55,-128],[55,-118],[55,-105],[55,-95],[55,-82],[55,-70],
        [50,-126],[50,-118],[50,-108],[50,-96],[50,-82],[50,-70],[50,-60],
        // ── North America: CONUS ──────────────────────────────────────────
        [48,-124],[48,-116],[48,-108],[48,-98],[48,-88],[48,-80],
        [46,-124],[46,-114],[46,-104],[46,-95],[46,-82],[46,-73],
        [44,-124],[44,-114],[44,-103],[44,-92],[44,-80],[44,-72],
        [42,-124],[42,-115],[42,-105],[42,-95],[42,-80],[42,-72],
        [40,-124],[40,-116],[40,-106],[40,-96],[40,-84],[40,-76],
        [38,-123],[38,-114],[38,-105],[38,-95],[38,-84],[38,-76],
        [36,-122],[36,-114],[36,-105],[36,-95],[36,-85],[36,-76],
        [34,-120],[34,-112],[34,-104],[34,-94],[34,-84],[34,-77],
        [32,-118],[32,-106],[32,-95],[32,-84],[30,-99],[30,-88],[30,-82],
        [28,-98],[28,-84],[26,-80],[25,-80],
        // ── Mexico and Central America ────────────────────────────────────
        [30,-111],[28,-111],[25,-104],[22,-100],[20,-101],[20,-90],
        [18,-95],[16,-92],[14,-90],[12,-86],[10,-84],[9,-80],
        // ── South America ─────────────────────────────────────────────────
        [10,-73],[8,-63],[6,-55],[3,-52],[0,-50],
        [-5,-45],[-8,-36],[-10,-38],[-12,-38],
        [-15,-46],[-15,-55],[-18,-46],[-18,-52],
        [-20,-44],[-20,-50],[-20,-64],[-22,-44],
        [-23,-46],[-25,-48],[-25,-65],[-28,-52],[-28,-65],
        [-32,-58],[-32,-68],[-35,-58],[-38,-58],[-38,-68],
        [-42,-64],[-45,-68],[-50,-68],[-52,-68],
        // ── Greenland ────────────────────────────────────────────────────
        [76,-42],[74,-54],[72,-52],[70,-50],[68,-48],[66,-44],
        // ── Iceland ──────────────────────────────────────────────────────
        [65,-18],[64,-20],[64,-14],[63,-22],
        // ── Europe: Scandinavia ───────────────────────────────────────────
        [70,28],[68,22],[68,15],[65,14],[63,12],[62,8],[60,6],[58,6],[57,10],[56,10],
        [55,8],[54,10],[53,8],[53,14],[52,10],[52,14],[51,4],[51,10],[51,14],
        // ── Europe: British Isles ─────────────────────────────────────────
        [58,-4],[56,-4],[54,-6],[53,-4],[52,-2],[51,-2],[50,-4],
        // ── Europe: Iberian Peninsula ─────────────────────────────────────
        [44,-8],[42,-8],[40,-8],[38,-8],[38,-5],[36,-5],[36,-8],
        // ── Europe: Continental ───────────────────────────────────────────
        [50,5],[50,8],[50,12],[50,16],[50,20],[50,24],
        [48,2],[48,8],[48,12],[48,16],[48,20],[48,24],
        [46,2],[46,7],[46,11],[46,15],[46,20],[46,24],
        [44,8],[44,12],[44,16],[44,20],[44,24],[44,28],
        [42,2],[42,12],[42,16],[42,20],[42,28],
        [40,14],[40,20],[40,28],[38,14],[38,20],[38,28],
        [36,14],[36,-6],
        // ── Eastern Europe / Russia West ──────────────────────────────────
        [68,40],[65,38],[62,36],[60,30],[58,30],[55,30],[55,38],[52,30],[52,36],[50,30],[50,36],
        // ── Turkey / Caucasus ─────────────────────────────────────────────
        [42,36],[40,32],[40,36],[40,40],[40,44],[38,34],[38,38],[38,44],[36,34],[36,38],[36,42],
        // ── Russia: Broad Coverage ────────────────────────────────────────
        [68,50],[68,62],[68,75],[68,90],[68,105],[68,120],[68,135],[68,150],[68,162],
        [65,50],[65,62],[65,75],[65,90],[65,105],[65,120],[65,135],[65,148],[65,158],
        [60,50],[60,62],[60,75],[60,90],[60,105],[60,120],[60,135],[60,150],
        [55,55],[55,65],[55,80],[55,95],[55,110],[55,128],[55,142],
        [50,58],[50,70],[50,85],[50,100],[50,118],[50,135],
        // ── Middle East ───────────────────────────────────────────────────
        [38,34],[36,38],[36,42],[34,36],[32,35],[32,38],[32,44],[30,47],
        [28,34],[28,46],[24,46],[24,56],[22,48],[20,42],
        [36,48],[34,48],[32,48],[30,52],[28,60],[26,64],[24,62],[24,68],
        // ── South Asia ───────────────────────────────────────────────────
        [35,70],[32,72],[30,74],[28,72],[28,78],[26,72],[26,80],[24,72],[24,78],[24,84],
        [22,72],[22,78],[22,82],[22,88],[20,78],[20,82],[18,78],[18,82],[16,80],
        [14,76],[14,80],[12,76],[12,80],[10,78],[8,78],
        // ── East Asia ─────────────────────────────────────────────────────
        [50,118],[48,118],[46,124],[44,118],[44,125],
        [42,118],[42,124],[40,116],[40,120],[38,114],[38,120],
        [35,108],[35,112],[35,118],[35,122],[32,110],[32,116],
        [30,106],[30,112],[30,118],[28,108],[28,114],
        [25,108],[25,114],[22,108],[22,112],[20,108],[20,112],
        // ── Japan and Korea ───────────────────────────────────────────────
        [44,142],[42,140],[40,140],[38,138],[38,140],[36,136],[36,138],[34,132],[34,136],
        [38,126],[36,126],[34,126],[32,126],
        // ── Southeast Asia: Mainland ──────────────────────────────────────
        [22,100],[20,100],[18,100],[16,104],[14,102],[12,100],[10,100],[8,100],[6,102],
        [4,104],[2,104],[0,104],[-2,106],[-4,108],[-6,108],[-8,118],
        [14,108],[12,108],[10,106],[8,124],[4,118],
        // ── Philippines ──────────────────────────────────────────────────
        [18,120],[16,120],[14,120],[12,124],[10,124],[8,126],
        // ── Indonesia ────────────────────────────────────────────────────
        [-6,106],[-8,112],[-8,116],[-8,120],[-8,124],[-8,128],[-8,132],[-8,136],
        [-10,120],[-10,124],[-10,128],[-10,134],[-6,140],[-4,140],
        // ── Africa: North ─────────────────────────────────────────────────
        [36,10],[34,10],[34,14],[32,12],[32,20],[30,28],[30,32],
        [28,20],[28,30],[24,12],[24,22],[22,14],[22,20],[22,30],[22,38],
        [20,14],[20,22],[20,30],[20,38],[18,14],[18,22],[18,30],[18,38],
        // ── Africa: West ─────────────────────────────────────────────────
        [16,14],[16,24],[14,14],[14,22],[12,14],[12,22],[12,38],
        [10,14],[10,22],[8,14],[8,22],[8,38],[6,10],[6,22],[4,10],[4,20],
        [2,10],[2,18],[0,10],[0,20],[-2,10],[-2,18],
        // ── Africa: Central and East ──────────────────────────────────────
        [-4,14],[-4,18],[-4,34],[-6,14],[-6,20],[-6,34],
        [-8,14],[-8,20],[-8,34],[-10,14],[-10,20],[-10,34],
        [-12,14],[-12,34],[-14,14],[-14,34],[-16,14],[-16,34],
        [-18,20],[-18,34],[-20,20],[-20,34],[-22,20],[-22,30],
        [-24,28],[-26,28],[-28,22],[-28,30],[-30,18],[-30,26],
        [-32,18],[-32,26],[-34,20],[-34,26],
        // ── Madagascar ───────────────────────────────────────────────────
        [-14,50],[-16,48],[-18,46],[-20,44],[-22,44],[-24,44],[-26,46],
        // ── Australia ────────────────────────────────────────────────────
        [-14,128],[-14,134],[-16,130],[-16,136],[-18,124],[-18,130],[-18,136],
        [-20,118],[-20,128],[-20,136],[-22,116],[-22,124],[-22,136],[-22,148],
        [-24,116],[-24,130],[-24,150],[-26,116],[-26,130],[-26,150],
        [-28,116],[-28,122],[-28,130],[-28,150],[-30,116],[-30,136],[-30,148],
        [-32,116],[-32,136],[-32,148],[-34,116],[-34,138],[-34,150],
        [-36,142],[-36,148],[-38,140],[-38,146],[-40,144],
        // ── New Zealand ──────────────────────────────────────────────────
        [-36,174],[-38,176],[-40,176],[-42,172],[-44,170],[-46,168],
    ];

    // ─────────────────────────────────────────────────────────────────────────
    // DEFAULT GEOGRAPHIC NODES
    //
    // Demo-mode node positions defined purely by latitude/longitude.
    // No city names, country names, or labels are stored here.
    // The backend API will supply real geographic metadata through setNodes().
    //
    // These positions are chosen to distribute nodes across all inhabited
    // continents, providing maximum visual coverage in demo mode.
    // ─────────────────────────────────────────────────────────────────────────

    var DEFAULT_NODES = [
        { lat:  40.7,  lon:  -74.0, id: 'n01' },   // North America East
        { lat:  37.8,  lon: -122.4, id: 'n02' },   // North America West
        { lat:  51.5,  lon:   -0.1, id: 'n03' },   // Western Europe
        { lat:  48.8,  lon:    2.3, id: 'n04' },   // Central Europe
        { lat:  55.7,  lon:   37.6, id: 'n05' },   // Eastern Europe
        { lat:  39.9,  lon:  116.4, id: 'n06' },   // East Asia
        { lat:  35.7,  lon:  139.7, id: 'n07' },   // Northeast Asia
        { lat:   1.3,  lon:  103.8, id: 'n08' },   // Southeast Asia
        { lat:  28.6,  lon:   77.2, id: 'n09' },   // South Asia
        { lat: -23.5,  lon:  -46.6, id: 'n10' },   // South America
        { lat: -33.9,  lon:  151.2, id: 'n11' },   // Oceania
        { lat:   6.5,  lon:    3.4, id: 'n12' },   // West Africa
    ];

    // ─────────────────────────────────────────────────────────────────────────
    // ENGINE STATE
    // ─────────────────────────────────────────────────────────────────────────

    var canvas, ctx, W, H;
    var staticCanvas, staticCtx;
    var geoNodes   = DEFAULT_NODES.slice();
    var activeArcs = [];
    var animId     = null;
    var frame      = 0;
    var opts       = Object.assign({}, DEFAULTS);

    // ─────────────────────────────────────────────────────────────────────────
    // GEOGRAPHIC PROJECTION
    //
    // Equirectangular projection mapping geographic coordinates to canvas pixels.
    // Latitude range: +80°N (top of canvas) to -55°S (bottom of canvas).
    // This range captures all major inhabited land masses without wasting
    // canvas space on the polar regions or deep Southern Ocean.
    //
    // When the backend provides real lat/lon data via addThreat(), the same
    // projection is used so that backend coordinates map correctly.
    // ─────────────────────────────────────────────────────────────────────────

    var LAT_MAX   =  80;   // Degrees north — top of canvas
    var LAT_MIN   = -55;   // Degrees south — bottom of canvas
    var LAT_RANGE = LAT_MAX - LAT_MIN;   // 135 degrees total

    /**
     * Convert [lat, lon] to { x, y } canvas pixel coordinates.
     * @param   {number} lat  Latitude  in decimal degrees  [-90, 90]
     * @param   {number} lon  Longitude in decimal degrees  [-180, 180]
     * @returns {{ x: number, y: number }}
     */
    function project(lat, lon) {
        var x = (lon + 180) / 360 * W;
        var y = (LAT_MAX - lat) / LAT_RANGE * H;
        return { x: x, y: y };
    }

    // ─────────────────────────────────────────────────────────────────────────
    // STATIC LAYER
    // Rendered once into an offscreen canvas, then blitted each animation frame.
    // Contains: grid lines + world-map dot matrix.
    // ─────────────────────────────────────────────────────────────────────────

    function buildStaticLayer() {
        staticCanvas.width  = W;
        staticCanvas.height = H;
        staticCtx.clearRect(0, 0, W, H);

        // ── Subtle grid ──
        var gridSize = Math.round(Math.min(W, H) / 14);
        staticCtx.strokeStyle = C.WHITE + '0.022)';
        staticCtx.lineWidth   = 1;
        for (var gx = 0; gx < W; gx += gridSize) {
            staticCtx.beginPath();
            staticCtx.moveTo(gx, 0);
            staticCtx.lineTo(gx, H);
            staticCtx.stroke();
        }
        for (var gy = 0; gy < H; gy += gridSize) {
            staticCtx.beginPath();
            staticCtx.moveTo(0, gy);
            staticCtx.lineTo(W, gy);
            staticCtx.stroke();
        }

        // ── World map dot matrix ──
        // Dot radius scales with canvas size so it looks consistent at all resolutions.
        var dotR = Math.max(1.2, Math.min(2.2, W / 900));
        staticCtx.fillStyle = C.CYAN + '0.11)';

        for (var i = 0; i < WORLD_DOTS.length; i++) {
            var pt = project(WORLD_DOTS[i][0], WORLD_DOTS[i][1]);
            if (pt.x < -dotR || pt.x > W + dotR) continue;
            if (pt.y < -dotR || pt.y > H + dotR) continue;
            staticCtx.beginPath();
            staticCtx.arc(pt.x, pt.y, dotR, 0, Math.PI * 2);
            staticCtx.fill();
        }
    }

    // ─────────────────────────────────────────────────────────────────────────
    // GEOGRAPHIC NODES
    // Animated pulsing dots drawn at each geo-node position.
    // ─────────────────────────────────────────────────────────────────────────

    function drawNodes() {
        for (var i = 0; i < geoNodes.length; i++) {
            var node  = geoNodes[i];
            var pt    = project(node.lat, node.lon);
            var col   = (SEVERITY_COL[node.severity] || C.CYAN);
            var r     = opts.nodeSize;

            // Stagger each node's phase to avoid synchronised pulsing
            var phase = (frame / 90 + i * 0.53) * Math.PI * 2;
            var pulse = 0.6 + 0.4 * Math.sin(phase);

            // Ambient halo
            var grad = ctx.createRadialGradient(pt.x, pt.y, 0, pt.x, pt.y, r * 6);
            grad.addColorStop(0, col + (0.2 * pulse) + ')');
            grad.addColorStop(1, col + '0)');
            ctx.beginPath();
            ctx.arc(pt.x, pt.y, r * 6, 0, Math.PI * 2);
            ctx.fillStyle = grad;
            ctx.fill();

            // Outer pulsing ring
            ctx.beginPath();
            ctx.arc(pt.x, pt.y, r * (1.8 + 0.5 * pulse), 0, Math.PI * 2);
            ctx.strokeStyle = col + (0.35 * pulse) + ')';
            ctx.lineWidth   = 0.9;
            ctx.stroke();

            // Core dot
            ctx.beginPath();
            ctx.arc(pt.x, pt.y, r, 0, Math.PI * 2);
            ctx.fillStyle = col + (0.92 * pulse) + ')';
            ctx.fill();
        }
    }

    // ─────────────────────────────────────────────────────────────────────────
    // BEZIER ARC UTILITIES
    // ─────────────────────────────────────────────────────────────────────────

    /**
     * Evaluate a quadratic Bezier at parameter t.
     * B(t) = (1-t)² P0 + 2(1-t)t CP + t² P1
     */
    function bezier(x0, y0, cpx, cpy, x1, y1, t) {
        var mt = 1 - t;
        return {
            x: mt * mt * x0 + 2 * mt * t * cpx + t * t * x1,
            y: mt * mt * y0 + 2 * mt * t * cpy + t * t * y1,
        };
    }

    /**
     * Build a control point that arcs the connection above the chord midpoint.
     * The lift scales with the chord length, producing short flat arcs and
     * long high arcs — mimicking great-circle appearance on the flat projection.
     */
    function makeArcCP(x0, y0, x1, y1) {
        var mx   = (x0 + x1) / 2;
        var my   = (y0 + y1) / 2;
        var dist = Math.sqrt((x1 - x0) * (x1 - x0) + (y1 - y0) * (y1 - y0));
        var lift = dist * 0.30; // Control arc height
        return { cpx: mx, cpy: my - lift };
    }

    // ─────────────────────────────────────────────────────────────────────────
    // CONNECTION ARC CREATION
    // ─────────────────────────────────────────────────────────────────────────

    /**
     * Create a new animated arc between two screen-space points.
     * @param {{ x, y }} src
     * @param {{ x, y }} dst
     * @param {string}   severity  'low'|'medium'|'high'|'critical'
     */
    function makeArc(src, dst, severity) {
        var cp  = makeArcCP(src.x, src.y, dst.x, dst.y);
        var col = SEVERITY_COL[severity] || C.CYAN;
        return {
            sx: src.x, sy: src.y,
            dx: dst.x, dy: dst.y,
            cpx: cp.cpx, cpy: cp.cpy,
            col:      col,
            t:        0,
            speed:    (opts.arcSpeed * (0.35 + Math.random() * 0.45)) / 1000,
            life:     1.0,
            holdFrames: 90 + Math.floor(Math.random() * 60),
        };
    }

    // ─────────────────────────────────────────────────────────────────────────
    // CONNECTION ARC RENDERING
    // ─────────────────────────────────────────────────────────────────────────

    function drawArcs() {
        // Filter fully decayed arcs
        var alive = [];
        for (var i = 0; i < activeArcs.length; i++) {
            if (activeArcs[i].life > 0) alive.push(activeArcs[i]);
        }
        activeArcs = alive;

        for (var ai = 0; ai < activeArcs.length; ai++) {
            var arc = activeArcs[ai];

            // Advance packet
            arc.t = Math.min(1, arc.t + arc.speed * 60);

            // Hold at end before decaying
            if (arc.t >= 1) {
                arc.holdFrames--;
                if (arc.holdFrames <= 0) arc.life -= 0.025;
            }

            var op = arc.life;

            // ── Draw trail (arc path from origin to packet tip) ──
            var SEGS = 36;
            ctx.lineWidth = 1.1;
            var prevPt = { x: arc.sx, y: arc.sy };

            for (var s = 1; s <= SEGS; s++) {
                var st   = (s / SEGS) * arc.t;
                var pt   = bezier(arc.sx, arc.sy, arc.cpx, arc.cpy, arc.dx, arc.dy, st);
                var segA = op * (0.04 + 0.14 * (s / SEGS));

                ctx.beginPath();
                ctx.moveTo(prevPt.x, prevPt.y);
                ctx.lineTo(pt.x, pt.y);
                ctx.strokeStyle = arc.col + segA + ')';
                ctx.stroke();
                prevPt = pt;
            }

            // ── Data packet (glowing dot at leading edge) ──
            if (arc.t < 1.0) {
                var tip = bezier(arc.sx, arc.sy, arc.cpx, arc.cpy, arc.dx, arc.dy, arc.t);

                // Glow
                var pg = ctx.createRadialGradient(tip.x, tip.y, 0, tip.x, tip.y, 7);
                pg.addColorStop(0, arc.col + (0.65 * op) + ')');
                pg.addColorStop(1, arc.col + '0)');
                ctx.beginPath();
                ctx.arc(tip.x, tip.y, 7, 0, Math.PI * 2);
                ctx.fillStyle = pg;
                ctx.fill();

                // Core
                ctx.beginPath();
                ctx.arc(tip.x, tip.y, 2.5, 0, Math.PI * 2);
                ctx.fillStyle = arc.col + (0.95 * op) + ')';
                ctx.fill();
            }

            // ── Destination pulse when packet arrives ──
            if (arc.t >= 1.0 && arc.holdFrames > 60) {
                var tAge   = 1 - (arc.holdFrames - 60) / 30;
                var ripple = 4 + tAge * 12;
                ctx.beginPath();
                ctx.arc(arc.dx, arc.dy, ripple, 0, Math.PI * 2);
                ctx.strokeStyle = arc.col + ((1 - tAge) * 0.5 * op) + ')';
                ctx.lineWidth   = 1.2;
                ctx.stroke();
            }
        }
    }

    // ─────────────────────────────────────────────────────────────────────────
    // DEMO-MODE ARC SCHEDULER
    // Randomly activates arcs between geo nodes when no backend data is present.
    // ─────────────────────────────────────────────────────────────────────────

    function scheduleRandomArc() {
        if (geoNodes.length < 2)            return;
        if (activeArcs.length >= opts.maxArcs) return;

        var src, dst, tries = 0;
        do {
            src = geoNodes[Math.floor(Math.random() * geoNodes.length)];
            dst = geoNodes[Math.floor(Math.random() * geoNodes.length)];
            tries++;
        } while (src === dst && tries < 20);

        if (src !== dst) {
            // Demo: bias toward lower severities (informational arcs)
            var sevs  = ['low', 'low', 'medium', 'medium', 'high', 'critical'];
            var sev   = sevs[Math.floor(Math.random() * sevs.length)];
            var srcPt = project(src.lat, src.lon);
            var dstPt = project(dst.lat, dst.lon);
            activeArcs.push(makeArc(srcPt, dstPt, sev));
        }
    }

    // ─────────────────────────────────────────────────────────────────────────
    // AMBIENT RADIAL GLOWS
    // Subtle fixed glow regions behind continents to add depth.
    // ─────────────────────────────────────────────────────────────────────────

    function drawAmbientGlows() {
        var glows = [
            { x: W * 0.20, y: H * 0.38, r: W * 0.22, a: 0.035 },   // Americas
            { x: W * 0.48, y: H * 0.32, r: W * 0.18, a: 0.030 },   // Europe / Africa
            { x: W * 0.73, y: H * 0.40, r: W * 0.25, a: 0.025 },   // Asia
        ];
        for (var gi = 0; gi < glows.length; gi++) {
            var g   = glows[gi];
            var gr  = ctx.createRadialGradient(g.x, g.y, 0, g.x, g.y, g.r);
            gr.addColorStop(0, C.BLUE + g.a + ')');
            gr.addColorStop(1, C.BLUE + '0)');
            ctx.beginPath();
            ctx.arc(g.x, g.y, g.r, 0, Math.PI * 2);
            ctx.fillStyle = gr;
            ctx.fill();
        }
    }

    // ─────────────────────────────────────────────────────────────────────────
    // MAIN ANIMATION LOOP
    // ─────────────────────────────────────────────────────────────────────────

    function tick() {
        frame++;
        ctx.clearRect(0, 0, W, H);

        // Layer 1: Static (blitted from offscreen canvas — very fast)
        ctx.drawImage(staticCanvas, 0, 0);

        // Layer 2: Ambient continental glow
        drawAmbientGlows();

        // Layer 3: Animated geo nodes
        drawNodes();

        // Layer 4: Connection arcs + data packets
        drawArcs();

        // Schedule new demo arcs periodically (~every 2 seconds at 60fps)
        if (frame % 120 === 0) scheduleRandomArc();

        // Ensure at least one arc is always active in demo mode
        if (activeArcs.length === 0 && frame > 60) scheduleRandomArc();

        animId = requestAnimationFrame(tick);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // RESIZE HANDLER
    // ─────────────────────────────────────────────────────────────────────────

    function resize() {
        W = canvas.width  = window.innerWidth;
        H = canvas.height = window.innerHeight;
        buildStaticLayer();
    }

    // ─────────────────────────────────────────────────────────────────────────
    // PUBLIC API
    // ─────────────────────────────────────────────────────────────────────────

    /**
     * Initialize the canvas engine.
     *
     * @param {string} canvasId - The id attribute of the target <canvas> element.
     * @param {object} [options] - Override default configuration.
     */
    function init(canvasId, options) {
        canvas = document.getElementById(canvasId);
        if (!canvas) {
            console.warn('[CyberBuddyMap] Canvas element not found:', canvasId);
            return;
        }
        ctx  = canvas.getContext('2d');
        opts = Object.assign({}, DEFAULTS, options || {});

        // Create offscreen canvas for the static layer
        staticCanvas = document.createElement('canvas');
        staticCtx    = staticCanvas.getContext('2d');

        // Initial paint
        resize();

        // Seed the visualization with arcs immediately for visual impact
        setTimeout(scheduleRandomArc, 500);
        setTimeout(scheduleRandomArc, 1200);
        setTimeout(scheduleRandomArc, 2200);

        // Start animation
        if (animId) cancelAnimationFrame(animId);
        animId = requestAnimationFrame(tick);

        // Respond to viewport changes
        window.addEventListener('resize', function () {
            cancelAnimationFrame(animId);
            resize();
            animId = requestAnimationFrame(tick);
        });
    }

    /**
     * Replace the current geographic nodes with data from the backend.
     *
     * @param {Array<{ lat: number, lon: number, id: string, severity?: string }>} nodeArray
     *   - lat:      Decimal latitude  [-90, 90]
     *   - lon:      Decimal longitude [-180, 180]
     *   - id:       Unique identifier for the node
     *   - severity: Optional — affects node color: 'low'|'medium'|'high'|'critical'
     *
     * TODO (Phase 1.2): Call this with live node data from the threat-intel backend.
     */
    function setNodes(nodeArray) {
        if (!Array.isArray(nodeArray) || nodeArray.length < 2) {
            console.warn('[CyberBuddyMap] setNodes() requires an array of at least 2 nodes.');
            return;
        }
        geoNodes   = nodeArray;
        activeArcs = [];  // Clear stale arcs when topology changes
    }

    /**
     * Add a single threat connection arc triggered by a backend event.
     *
     * @param {object} threat
     * @param {number} threat.srcLat    Source latitude  in decimal degrees
     * @param {number} threat.srcLon    Source longitude in decimal degrees
     * @param {number} threat.dstLat    Destination latitude  in decimal degrees
     * @param {number} threat.dstLon    Destination longitude in decimal degrees
     * @param {string} [threat.severity] 'low'|'medium'|'high'|'critical'
     * @param {string} [threat.type]     Threat type label (reserved for future UI use)
     * @param {string} [threat.timestamp] ISO 8601 timestamp (reserved for future UI use)
     *
     * TODO (Phase 1.2): Wire to VirusTotal / AbuseIPDB / OTX backend events.
     */
    function addThreat(threat) {
        if (!canvas) {
            console.warn('[CyberBuddyMap] Call init() before addThreat().');
            return;
        }
        var srcPt = project(threat.srcLat, threat.srcLon);
        var dstPt = project(threat.dstLat, threat.dstLon);
        activeArcs.push(makeArc(srcPt, dstPt, threat.severity || 'medium'));
    }

    /**
     * Remove all active threat arcs immediately.
     * Useful when the user navigates to a new view or resets the feed.
     */
    function clearThreats() {
        activeArcs = [];
    }

    /**
     * Stop the animation loop and release resources.
     * Call this before removing the canvas element from the DOM.
     */
    function destroy() {
        if (animId) cancelAnimationFrame(animId);
        animId = null;
        canvas = ctx = staticCanvas = staticCtx = null;
    }

    // Expose on the global window object
    global.CyberBuddyMap = {
        init:          init,
        setNodes:      setNodes,
        addThreat:     addThreat,
        clearThreats:  clearThreats,
        destroy:       destroy,
    };

}(window));
