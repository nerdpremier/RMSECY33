// --- Collector Variables ---
let mouseIntervals = [], clickIntervals = [], keyIntervals = [], idleDurations = [];
let lastMouse = null, lastClick = null, lastKey = null, lastActivity = Date.now();
const sessionStart = Date.now();

// --- Listeners ---
document.addEventListener("mousemove", () => {
    let now = Date.now();
    if (lastMouse) mouseIntervals.push(now - lastMouse);
    lastMouse = now; lastActivity = now;
});
document.addEventListener("mousedown", () => {
    let now = Date.now();
    if (lastClick) clickIntervals.push(now - lastClick);
    lastClick = now; lastActivity = now;
});
document.addEventListener("keydown", () => {
    let now = Date.now();
    if (lastKey) keyIntervals.push(now - lastKey);
    lastKey = now; lastActivity = now;
});

setInterval(() => {
    let idle = Date.now() - lastActivity;
    if (idle > 1000) {
        idleDurations.push(idle);
        lastActivity = Date.now();
    }
}, 1000);

// --- Math Helpers ---
function percentile(arr, p) {
    let s = [...arr].sort((a, b) => a - b);
    if (!s.length) return 0;
    let i = (p / 100) * (s.length - 1);
    let l = Math.floor(i), u = Math.ceil(i);
    return l === u ? s[i] : s[l] + (s[u] - s[l]) * (i - l);
}

function removeOutliers(arr) {
    if (arr.length < 4) return arr;
    let Q1 = percentile(arr, 25), Q3 = percentile(arr, 75);
    let IQR = Q3 - Q1;
    return arr.filter(v => v >= (Q1 - 1.5 * IQR) && v <= (Q3 + 1.5 * IQR));
}

function getStats(raw, type = "general") {
    const fallback = { m: 0, s: 0 };
    if (!raw || raw.length < 2) return fallback;
    let filtered = raw;
    if (type === "click") filtered = raw.filter(v => v >= 60);
    if (type === "mouse") filtered = raw.filter(v => v >= 1);
    let f = removeOutliers(filtered);
    if (f.length < 2) return fallback;
    let m = f.reduce((a, b) => a + b, 0) / f.length;
    let v = f.reduce((a, b) => a + (b - m) ** 2, 0) / f.length;
    let s = Math.sqrt(v);
    const limits = {
        click: { max_m: 2000, max_s: 500 },
        mouse: { max_m: 100,  max_s: 50 },
        key:   { max_m: 1000, max_s: 300 },
        idle:  { max_m: 10000, max_s: 2000 },
        general: { max_m: 1000, max_s: 300 }
    };
    const L = limits[type] || limits.general;
    // ปรับเหลือ 3 ตำแหน่ง
    return {
        m: parseFloat((Math.min(Math.max(m / L.max_m, 0), 1)).toFixed(3)),
        s: parseFloat((Math.min(Math.max(s / L.max_s, 0), 1)).toFixed(3))
    };
}

// --- Game Engine ---
const stages = [
    { name: "คลิกเป้าหมาย 10 จุด 🎯", desc: "", type: "click" },
    { name: "ลากเมาส์ตามเป้าหมาย 🛸", desc: "", time: 10, type: "move" },
    { name: "พิมพ์คำที่ปรากฏให้ถูกต้อง ⌨️", desc: "", type: "type" },
    { name: "กดปุ่มที่คีย์บอร์ดค้าง 🎹", desc: "", type: "key_rhythm" },
    { name: "ลากเมาส์ตามทาง: ห้ามออกนอกเส้นทาง 🖋️", desc: "", type: "steady_path" }
];
let currentStage = 0, timer = null;

function renderStage() {
    const area = document.getElementById("challengeArea");
    if (currentStage >= stages.length) {
        area.innerHTML = `<div class="card"><span style="font-size:4rem">🏆</span><h2>เสร็จสมบูรณ์</h2><p id="final-msg">กำลังประมวลผลข้อมูลสถิติ...</p></div>`;
        autoExportData();
        return;
    }
    let s = stages[currentStage];
    area.innerHTML = `<div class="card"><small>ด่าน ${currentStage + 1} / ${stages.length}</small><h2>${s.name}</h2><p>${s.desc}</p><div class="timer" id="timeDisplay">${s.time ? s.time+'s' : '--'}</div><div id="gameCanvas"><button class="main-btn" style="margin-top:140px" onclick="startStage()">เริ่มภารกิจ</button></div></div>`;
}

function startStage() {
    let s = stages[currentStage];
    const cv = document.getElementById("gameCanvas");
    cv.innerHTML = "";
    if (s.type === "click") initClick(cv);
    if (s.type === "move") initMove(cv);
    if (s.type === "type") initType(cv);
    if (s.type === "key_rhythm") initKeyRhythm(cv);
    if (s.type === "steady_path") initSteadyPath(cv);
    if (s.time) {
        let timeLeft = s.time;
        timer = setInterval(() => {
            timeLeft--;
            document.getElementById("timeDisplay").innerText = timeLeft + "s";
            if (timeLeft <= 0) finishStage();
        }, 1000);
    }
}

function finishStage() {
    clearInterval(timer);
    currentStage++;
    document.getElementById("overallBar").style.width = (currentStage / stages.length * 100) + "%";
    renderStage();
}

function initClick(cv) {
    let count = 0;
    function spawn() {
        cv.innerHTML = `<div style="padding:15px">แต้ม: ${count}/10</div>`;
        let t = document.createElement("div");
        t.className = "target";
        t.style.left = Math.random() * 85 + "%";
        t.style.top = Math.random() * 60 + 20 + "%";
        t.innerText = "🎯";
        t.onmousedown = () => { count++; if (count < 10) spawn(); else finishStage(); };
        cv.appendChild(t);
    }
    spawn();
}

function initMove(cv) {
    let t = document.createElement("div");
    t.className = "target"; t.innerText = "🛸"; cv.appendChild(t);
    let a = 0;
    function anim() {
        if (currentStage !== 1) return;
        a += 0.015;
        t.style.left = (50 + Math.cos(a) * 35) + "%";
        t.style.top = (50 + Math.sin(a * 0.8) * 35) + "%";
        requestAnimationFrame(anim);
    }
    anim();
}

function initType(cv) {
    const words = ["Cybersecurity", "Behavioral", "Authentication"];
    let idx = 0;
    function update() {
        cv.innerHTML = `<div style="margin-top:60px"><div style="font-size:2rem; color:var(--neon); margin-bottom:15px">${words[idx]}</div><input type="text" id="typer" autofocus autocomplete="off"></div>`;
        const input = document.getElementById("typer");
        input.focus();
        input.oninput = (e) => { if (e.target.value === words[idx]) { idx++; if (idx < words.length) update(); else finishStage(); } };
    }
    update();
}

function initKeyRhythm(cv) {
    let count = 0; 
    const keys = ["R", "M", "S", "E"];
    
    function next() {
        let k = keys[count];
        let displayKey = k === "Space" ? "␣" : k; // ใช้สัญลักษณ์สเปซบาร์ที่สวยขึ้น
        
        cv.innerHTML = `
            <div style="margin-top:40px">
                <p class="key-instruction">HOLD KEY TO CHARGE</p>
                <div id="keyVisual" class="rhythm-key-display">${displayKey}</div>
                <div style="width:200px; height:8px; background:#222; margin:20px auto; border-radius:10px; overflow:hidden;">
                    <div id="keyProg" style="width:0%; height:100%; background:var(--neon); transition: width 0.05s linear;"></div>
                </div>
            </div>
        `;

        const keyVisual = document.getElementById("keyVisual");
        const keyProg = document.getElementById("keyProg");
        let pressing = false, progress = 0, interval = null;

        const down = (e) => {
            let target = k === "Space" ? " " : k.toLowerCase();
            if (e.key.toLowerCase() === target && !pressing) {
                pressing = true;
                keyVisual.classList.add("active"); // เพิ่ม Effect เมื่อกด
                
                interval = setInterval(() => {
                    progress += 2.5; // ความเร็วในการชาร์จ
                    if(keyProg) keyProg.style.width = progress + "%";
                    
                    if (progress >= 100) {
                        clearInterval(interval);
                        window.removeEventListener("keydown", down);
                        window.removeEventListener("keyup", up);
                        count++; 
                        if (count < keys.length) next(); else finishStage();
                    }
                }, 20);
            }
        };

        const up = (e) => {
            let target = k === "Space" ? " " : k.toLowerCase();
            if (e.key.toLowerCase() === target) {
                pressing = false;
                keyVisual.classList.remove("active"); // เอา Effect ออกเมื่อปล่อย
                clearInterval(interval);
                progress = 0;
                if(keyProg) keyProg.style.width = "0%";
            }
        };

        window.addEventListener("keydown", down);
        window.addEventListener("keyup", up);
    }
    next();
}

function initSteadyPath(cv) {
    cv.innerHTML = `
        <div class="maze-container">
            <svg width="100%" height="100%" viewBox="0 0 600 360">
                <path class="maze-road" d="M 100 60 H 500 V 180 H 100 V 300 H 500" />
                <path id="mazeProgress" class="maze-progress" d="M 100 60 H 500 V 180 H 100 V 300 H 500" />
                <path id="mazeTrigger" class="maze-trigger" d="M 100 60 H 500 V 180 H 100 V 300 H 500" />
            </svg>
            <div id="start-node" class="maze-point" style="left:150px; top:60px; background:var(--accent); box-shadow: 0 0 15px var(--accent);">START</div>
            <div id="goal-node" class="maze-point" style="left:580px; top:300px; background:var(--neon); color:#000;">GOAL</div>
        </div>
    `;

    const trig = document.getElementById("mazeTrigger");
    const progressPath = document.getElementById("mazeProgress");
    const goal = document.getElementById("goal-node");
    const start = document.getElementById("start-node");
    
    // เตรียมความยาวเส้น
    const pathLength = progressPath.getTotalLength();
    progressPath.style.strokeDasharray = pathLength;
    progressPath.style.strokeDashoffset = pathLength;

    let isStarted = false;

    // ฟังก์ชันอัปเดตเส้นสีเขียวตามตำแหน่งเมาส์
    trig.onmousemove = (e) => {
        if (!isStarted) return;
        
        // คำนวณหาจุดที่ใกล้ที่สุดบนเส้น SVG เทียบกับพิกัดเมาส์
        const svg = trig.ownerSVGElement;
        const pt = svg.createSVGPoint();
        pt.x = e.clientX;
        pt.y = e.clientY;
        const loc = pt.matrixTransform(svg.getScreenCTM().inverse());
        
        // หาจุดที่ใกล้ที่สุดบน Path เพื่อเอาค่าระยะทาง (Distance)
        // หมายเหตุ: วิธีนี้เป็นแบบประมาณการที่เร็วและลื่นไหล
        const totalSteps = 200; 
        let minDest = Infinity;
        let bestLength = 0;
        
        for (let i = 0; i <= totalSteps; i++) {
            let l = (i / totalSteps) * pathLength;
            let p = progressPath.getPointAtLength(l);
            let d = Math.sqrt((loc.x - p.x)**2 + (loc.y - p.y)**2);
            if (d < minDest) {
                minDest = d;
                bestLength = l;
            }
        }
        
        // อัปเดตเส้น Progress (วาดเส้นออกมาตามระยะที่เมาส์ลากไปถึง)
        progressPath.style.strokeDashoffset = pathLength - bestLength;
    };

    start.onmouseenter = () => {
        isStarted = true;
        start.style.background = "var(--neon)";
        start.innerText = "GO!";
    };

    trig.onmouseleave = (e) => {
        if (isStarted && e.relatedTarget !== goal) {
            isStarted = false;
            // รีเซ็ตเส้นกลับเป็น 0
            progressPath.style.strokeDashoffset = pathLength;
            start.style.background = "red";
            start.innerText = "RETRY";
            setTimeout(() => { start.style.background = "var(--accent)"; }, 500);
        }
    };

    goal.onmouseenter = () => {
        if (isStarted) {
            isStarted = false;
            progressPath.style.strokeDashoffset = 0; // เติมให้เต็ม
            finishStage();
        }
    };
}

async function autoExportData() {
    const status = document.getElementById("save-status");
    const msg = document.getElementById("final-msg");
    status.innerText = "⏳ กำลังบันทึกข้อมูล ...";

    const totalTimeSec = (Date.now() - sessionStart) / 1000;
    const idleSum = idleDurations.reduce((a, b) => a + b, 0) / 1000;
    const idleRatio = idleSum / totalTimeSec;
    const rawDensity = (mouseIntervals.length + clickIntervals.length + keyIntervals.length) / totalTimeSec;

    const payload = {
        mouse: getStats(mouseIntervals, "mouse"),
        click: getStats(clickIntervals, "click"),
        key: getStats(keyIntervals, "key"),
        idle: getStats(idleDurations, "idle"),
        features: {
            density: parseFloat((rawDensity / 100).toFixed(3)),
            idle_ratio: parseFloat(idleRatio.toFixed(3))
        }
    };

    try {
        const res = await fetch("/api/save", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify(payload)
        });
        if (res.ok) {
            status.style.color = "var(--neon)";
            status.innerText = "✅ บันทึกสำเร็จ";
            msg.innerText = "ข้อมูลถูกส่งเข้าระบบเรียบร้อย";
        } else { throw new Error("Server Error"); }
    } catch (err) {
        status.style.color = "var(--accent)";
        status.innerText = "❌ ผิดพลาด: " + err.message;
        msg.innerHTML = `<button class="main-btn" onclick="autoExportData()">ลองใหม่</button>`;
    }
}

renderStage();