/*!
 * CyberBuddy Geo Intelligence Canvas Engine (v7.0 - V1 Design Baseline)
 */

(function (global) {
    'use strict';

    var C = {
        CYAN:    'rgba(6,182,212,',
        BLUE:    'rgba(59,130,246,',
        EMERALD: 'rgba(16,185,129,',
        AMBER:   'rgba(245,158,11,',
        ORANGE:  'rgba(249,115,22,',
        ROSE:    'rgba(244,63,94,',
        WHITE:   'rgba(248,250,252,'
    };
    var SEVERITY_COL = { low: C.EMERALD, medium: C.AMBER, high: C.ORANGE, critical: C.ROSE };

    var canvas, ctx, W, H;
    var staticCanvas, staticCtx;
    var animId = null;
    var lastTime = 0;
    var globalTime = 0;
    
    var worldData = null; // GeoJSON
    
    var LAT_MAX = 85;
    var LAT_MIN = -60;
    var LAT_RANGE = LAT_MAX - LAT_MIN;

    function project(lat, lon) {
        var x = (lon + 180) / 360 * W;
        var y = (LAT_MAX - lat) / LAT_RANGE * H;
        return { x: x, y: y };
    }

    var socPt = project(40.7128, -74.0060); // NYC
    
    // Core Internet Hubs
    var hubsCoords = [
        // US East
        [40.71, -74.00], [38.90, -77.03], [42.36, -71.05],
        // US West
        [37.77, -122.41], [34.05, -118.24], [47.60, -122.33],
        // Europe
        [51.50, -0.12], [50.11, 8.68], [48.85, 2.35], [52.36, 4.90],
        // Asia
        [35.68, 139.69], [1.35, 103.81], [22.31, 114.16], [31.23, 121.47], [19.07, 72.87],
        // South America / Africa / Oceania
        [-23.55, -46.63], [-34.60, -58.38],
        [-26.20, 28.04], [25.20, 55.27],
        [-33.86, 151.20]
    ];
    var hubs = hubsCoords.map(c => project(c[0], c[1]));

    var ambientPaths = [];
    var routePairs = [
        // US Transcontinental
        [0, 3], [0, 4], [1, 3], [2, 5],
        // Transatlantic
        [0, 6], [0, 7], [3, 10], [4, 11], [1, 8], [2, 6],
        // Europe Internal Heavy
        [6, 7], [6, 8], [7, 9], [8, 9],
        // Europe to Asia
        [7, 18], [18, 14], [14, 11], [18, 11], [6, 11],
        // Asia Internal Heavy
        [10, 11], [11, 12], [12, 13], [10, 13], [11, 14],
        // Global South
        [0, 15], [15, 16], [6, 17], [18, 17], [11, 19]
    ];
    
    routePairs.forEach(pair => {
        // Create multiple density paths for realism
        var density = Math.floor(Math.random() * 3) + 1;
        for(var i=0; i<density; i++) {
            ambientPaths.push({
                h1: hubs[pair[0]], h2: hubs[pair[1]],
                offset: Math.random() * 8000,
                duration: 2500 + Math.random() * 4000,
                color: Math.random() > 0.5 ? C.CYAN : C.BLUE
            });
            ambientPaths.push({
                h1: hubs[pair[1]], h2: hubs[pair[0]],
                offset: Math.random() * 8000,
                duration: 2500 + Math.random() * 4000,
                color: Math.random() > 0.5 ? C.CYAN : C.BLUE
            });
        }
    });

    var state = 0; 
    var stateTime = 0;
    var targetPt = null;
    var targetCol = C.CYAN;
    var targetSeverity = 'medium';
    var investigationHistory = []; 

    function init(canvasId) {
        canvas = document.getElementById(canvasId);
        if (!canvas) return;
        ctx = canvas.getContext('2d', { alpha: true });
        
        staticCanvas = document.createElement('canvas');
        staticCtx = staticCanvas.getContext('2d', { alpha: true });
        
        fetch('/static/world.geo.json')
            .then(res => res.json())
            .then(data => {
                worldData = data;
                resize();
                if (animId) cancelAnimationFrame(animId);
                lastTime = performance.now();
                animId = requestAnimationFrame(tick);
            })
            .catch(err => console.error("Failed to load map data:", err));
        
        window.addEventListener('resize', resize);
    }

    function resize() {
        if(!canvas || !worldData) return;
        W = canvas.width = window.innerWidth;
        H = canvas.height = window.innerHeight;
        
        socPt = project(40.7128, -74.0060);
        hubs = hubsCoords.map(c => project(c[0], c[1]));
        
        // Reproject paths
        var pathIdx = 0;
        routePairs.forEach(pair => {
            var density = Math.floor(Math.random() * 3) + 1;
            for(var i=0; i<density; i++) {
                if (ambientPaths[pathIdx]) { ambientPaths[pathIdx].h1 = hubs[pair[0]]; ambientPaths[pathIdx].h2 = hubs[pair[1]]; pathIdx++; }
                if (ambientPaths[pathIdx]) { ambientPaths[pathIdx].h1 = hubs[pair[1]]; ambientPaths[pathIdx].h2 = hubs[pair[0]]; pathIdx++; }
            }
        });
        buildStaticLayer();
    }

    function buildStaticLayer() {
        staticCanvas.width = W;
        staticCanvas.height = H;
        staticCtx.clearRect(0, 0, W, H);

        // Ocean Gradient (Deep subtle blue to black)
        var bgGrad = staticCtx.createLinearGradient(0, 0, 0, H);
        bgGrad.addColorStop(0, '#020617'); // Very dark slate
        bgGrad.addColorStop(0.5, '#051228'); // Deep midnight blue
        bgGrad.addColorStop(1, '#020617');
        staticCtx.fillStyle = bgGrad;
        staticCtx.fillRect(0, 0, W, H);

        // Grid Lines
        staticCtx.strokeStyle = 'rgba(255,255,255,0.02)';
        staticCtx.lineWidth = 1;
        for (var x = 0; x < W; x += W/20) {
            staticCtx.beginPath(); staticCtx.moveTo(x, 0); staticCtx.lineTo(x, H); staticCtx.stroke();
        }
        for (var y = 0; y < H; y += H/15) {
            staticCtx.beginPath(); staticCtx.moveTo(0, y); staticCtx.lineTo(W, y); staticCtx.stroke();
        }

        // Continents
        staticCtx.fillStyle = 'rgba(10, 25, 47, 0.6)';
        // Brighter coastlines
        staticCtx.strokeStyle = 'rgba(34, 211, 238, 0.35)';
        staticCtx.lineWidth = 1.2;

        worldData.features.forEach(feature => {
            if (feature.geometry.type === 'Polygon') {
                drawPolygon(feature.geometry.coordinates[0]);
            } else if (feature.geometry.type === 'MultiPolygon') {
                feature.geometry.coordinates.forEach(polygon => {
                    drawPolygon(polygon[0]);
                });
            }
        });

        function drawPolygon(points) {
            staticCtx.beginPath();
            points.forEach((pt, i) => {
                var projected = project(pt[1], pt[0]);
                if (i === 0) staticCtx.moveTo(projected.x, projected.y);
                else staticCtx.lineTo(projected.x, projected.y);
            });
            staticCtx.closePath();
            staticCtx.fill();
            staticCtx.stroke();
        }
        
        // Atmospheric Glow on continents
        staticCtx.shadowColor = 'rgba(6, 182, 212, 0.6)';
        staticCtx.shadowBlur = 15;
        staticCtx.strokeStyle = 'rgba(6, 182, 212, 0.15)';
        staticCtx.lineWidth = 2;
        worldData.features.forEach(feature => {
            if (feature.geometry.type === 'Polygon') {
                drawPolygonGlow(feature.geometry.coordinates[0]);
            }
        });
        staticCtx.shadowBlur = 0;
        
        function drawPolygonGlow(points) {
            staticCtx.beginPath();
            points.forEach((pt, i) => {
                var p = project(pt[1], pt[0]);
                if (i === 0) staticCtx.moveTo(p.x, p.y);
                else staticCtx.lineTo(p.x, p.y);
            });
            staticCtx.stroke();
        }
    }
    
    function easeOutExp(x) { return x === 1 ? 1 : 1 - Math.pow(2, -10 * x); }
    function easeInOutQuad(x) { return x < 0.5 ? 2 * x * x : 1 - Math.pow(-2 * x + 2, 2) / 2; }

    function drawAmbient(dt, dimFactor) {
        var op = 1.0 - (dimFactor * 0.85); 
        
        ambientPaths.forEach(path => {
            if (!path.h1 || !path.h2) return;
            var cpx = (path.h1.x + path.h2.x) / 2;
            var cpy = Math.min(path.h1.y, path.h2.y) - 60;
            
            // Faint static airline route
            ctx.beginPath();
            ctx.moveTo(path.h1.x, path.h1.y);
            ctx.quadraticCurveTo(cpx, cpy, path.h2.x, path.h2.y);
            ctx.strokeStyle = path.color + (0.1 * op) + ')';
            ctx.lineWidth = 0.5;
            ctx.stroke();

            // Telemetry Packets
            var p = ((globalTime + path.offset) % path.duration) / path.duration;
            if (p > 0 && p < 1) {
                var mt = 1 - p;
                var px = mt * mt * path.h1.x + 2 * mt * p * cpx + p * p * path.h2.x;
                var py = mt * mt * path.h1.y + 2 * mt * p * cpy + p * p * path.h2.y;
                
                ctx.beginPath();
                ctx.arc(px, py, 1.2, 0, Math.PI*2);
                ctx.fillStyle = '#fff';
                ctx.globalAlpha = op;
                ctx.fill();
                
                var grad = ctx.createRadialGradient(px, py, 0, px, py, 5);
                grad.addColorStop(0, path.color + '0.7)');
                grad.addColorStop(1, path.color + '0)');
                ctx.beginPath();
                ctx.arc(px, py, 5, 0, Math.PI*2);
                ctx.fillStyle = grad;
                ctx.fill();
                ctx.globalAlpha = 1.0;
            }
        });

        // Hubs Breathing
        hubs.forEach((hub, i) => {
            var pulse = Math.sin((globalTime + i*1500) / 1000) * 0.5 + 0.5;
            ctx.beginPath();
            ctx.arc(hub.x, hub.y, 2, 0, Math.PI*2);
            ctx.fillStyle = C.CYAN + (0.8 * op) + ')';
            ctx.fill();
            
            ctx.beginPath();
            ctx.arc(hub.x, hub.y, 5 + pulse*4, 0, Math.PI*2);
            ctx.strokeStyle = C.CYAN + (0.4 * op * (1-pulse)) + ')';
            ctx.lineWidth = 1;
            ctx.stroke();
        });
    }

    function drawHistory() {
        for (var i = investigationHistory.length - 1; i >= 0; i--) {
            var hist = investigationHistory[i];
            var age = globalTime - hist.t;
            var maxAge = 15000;
            if (age > maxAge) {
                investigationHistory.splice(i, 1);
                continue;
            }
            var op = 1.0 - (age / maxAge);
            
            ctx.beginPath();
            ctx.arc(hist.x, hist.y, 10, 0, Math.PI*2);
            ctx.fillStyle = hist.col + (0.15 * op) + ')';
            ctx.fill();
            
            ctx.beginPath();
            ctx.arc(hist.x, hist.y, 3, 0, Math.PI*2);
            ctx.fillStyle = hist.col + (0.7 * op) + ')';
            ctx.fill();
        }
    }

    function getQuadraticCurvePoint(startX, startY, cpX, cpY, endX, endY, position) {
        var t = position;
        var mt = 1 - t;
        var x = mt * mt * startX + 2 * mt * t * cpX + t * t * endX;
        var y = mt * mt * startY + 2 * mt * t * cpY + t * t * endY;
        return {x: x, y: y};
    }

    function drawInvestigation(dt, elapsed) {
        if (!targetPt) return;

        var cpx = (socPt.x + targetPt.x) / 2;
        var cpy = Math.min(socPt.y, targetPt.y) - 180;

        if (state === 1) { 
            // Scan Launch - Natural Growth
            var dur = 900;
            var t = Math.min(elapsed / dur, 1);
            t = easeInOutQuad(t);

            // Draw growing route by calculating points along the bezier
            ctx.beginPath();
            ctx.moveTo(socPt.x, socPt.y);
            var steps = 30;
            for(var i=1; i<=steps; i++) {
                var pos = (i/steps) * t;
                var pt = getQuadraticCurvePoint(socPt.x, socPt.y, cpx, cpy, targetPt.x, targetPt.y, pos);
                ctx.lineTo(pt.x, pt.y);
            }
            ctx.strokeStyle = C.CYAN + '0.8)';
            ctx.lineWidth = 3;
            ctx.stroke();

            // Head of the route
            var head = getQuadraticCurvePoint(socPt.x, socPt.y, cpx, cpy, targetPt.x, targetPt.y, t);
            var grad = ctx.createRadialGradient(head.x, head.y, 0, head.x, head.y, 35);
            grad.addColorStop(0, C.CYAN + '1.0)');
            grad.addColorStop(1, C.CYAN + '0.0)');
            ctx.fillStyle = grad;
            ctx.beginPath();
            ctx.arc(head.x, head.y, 35, 0, Math.PI*2);
            ctx.fill();

            ctx.beginPath();
            ctx.arc(head.x, head.y, 4, 0, Math.PI*2);
            ctx.fillStyle = '#fff';
            ctx.fill();
        } 
        else if (state === 2) { 
            // Target Locked (Fetching Intel)
            var pulse = Math.sin(elapsed / 120) * 0.5 + 0.5;
            
            // Solid Track
            ctx.beginPath();
            ctx.moveTo(socPt.x, socPt.y);
            ctx.quadraticCurveTo(cpx, cpy, targetPt.x, targetPt.y);
            ctx.strokeStyle = C.CYAN + '0.7)';
            ctx.lineWidth = 2;
            ctx.stroke();

            // Glowing Target Node
            ctx.beginPath();
            ctx.arc(targetPt.x, targetPt.y, 5, 0, Math.PI*2);
            ctx.fillStyle = '#fff';
            ctx.fill();
            
            ctx.beginPath();
            ctx.arc(targetPt.x, targetPt.y, 25 + pulse * 25, 0, Math.PI*2);
            ctx.strokeStyle = C.CYAN + (0.8 * (1-pulse)) + ')';
            ctx.lineWidth = 3.5;
            ctx.stroke();
            
            // Rapid Data Streams (SOC <-> Target)
            for (var i=0; i<4; i++) {
                var p = ((elapsed + i*130) % 520) / 520;
                var pt = getQuadraticCurvePoint(socPt.x, socPt.y, cpx, cpy, targetPt.x, targetPt.y, p);
                
                ctx.beginPath();
                ctx.arc(pt.x, pt.y, 3, 0, Math.PI*2);
                ctx.fillStyle = '#fff';
                ctx.fill();
                
                var trailGrad = ctx.createRadialGradient(pt.x, pt.y, 0, pt.x, pt.y, 12);
                trailGrad.addColorStop(0, C.CYAN + '0.9)');
                trailGrad.addColorStop(1, C.CYAN + '0.0)');
                ctx.fillStyle = trailGrad;
                ctx.beginPath();
                ctx.arc(pt.x, pt.y, 12, 0, Math.PI*2);
                ctx.fill();
            }
        }
        else if (state === 3) { 
            // Verdict Eruption
            var dur = 2000;
            var t = elapsed / dur;
            
            ctx.beginPath();
            ctx.arc(targetPt.x, targetPt.y, 6, 0, Math.PI*2);
            ctx.fillStyle = targetCol + '1.0)';
            ctx.fill();

            // Massive Ripple Rings
            for(var r=0; r<5; r++) {
                var rt = (t * 2.5 - (r * 0.15));
                if (rt > 0 && rt < 1) {
                    var ringP = easeOutExp(rt);
                    ctx.beginPath();
                    ctx.arc(targetPt.x, targetPt.y, 350 * ringP, 0, Math.PI*2);
                    ctx.strokeStyle = targetCol + (1 - ringP) + ')';
                    ctx.lineWidth = 6 - (r*1.0);
                    ctx.stroke();
                }
            }

            // Connection persists brightly then fades
            ctx.beginPath();
            ctx.moveTo(socPt.x, socPt.y);
            ctx.quadraticCurveTo(cpx, cpy, targetPt.x, targetPt.y);
            ctx.strokeStyle = targetCol + (1 - (t>1?1:t)) * 0.9 + ')';
            ctx.lineWidth = 3;
            ctx.stroke();
        }
    }

    function tick(now) {
        animId = requestAnimationFrame(tick);
        if (!canvas || !worldData) return;
        var dt = now - lastTime;
        lastTime = now;
        globalTime += dt;
        
        ctx.clearRect(0, 0, W, H);
        if (staticCanvas) {
            ctx.drawImage(staticCanvas, 0, 0);
        }
        
        var dimFactor = 0;
        if (state >= 1 && state <= 3) {
            dimFactor = 1.0; 
        }
        
        drawAmbient(dt, dimFactor);
        drawHistory();

        if (state > 0) {
            stateTime += dt;
            
            if (state === 1) { 
                drawInvestigation(dt, stateTime);
                if (stateTime > 900) transitionState(2);
            } 
            else if (state === 2) { 
                drawInvestigation(dt, stateTime);
            }
            else if (state === 3) { 
                drawInvestigation(dt, stateTime);
                if (stateTime > 2000) transitionState(4);
            }
            else if (state === 4) { 
                investigationHistory.push({x: targetPt.x, y: targetPt.y, col: targetCol, t: globalTime});
                transitionState(0);
            }
        }
    }

    function transitionState(newState) {
        state = newState;
        stateTime = 0;
    }

    function startInvestigation(lat, lon) {
        targetPt = project(lat, lon);
        transitionState(1);
    }
    
    function resolveInvestigation(severity) {
        targetSeverity = severity;
        targetCol = SEVERITY_COL[severity] || C.CYAN;
        transitionState(3); 
    }

    global.CyberBuddyMap = {
        init: init,
        startInvestigation: startInvestigation,
        resolveInvestigation: resolveInvestigation
    };

})(window);
