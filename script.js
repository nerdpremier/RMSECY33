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
    { name: "🎯 Click Hunt", desc: "คลิกเป้าหมาย 10 จุด", type: "click" },
    { name: "🛸 Orbital", desc: "ลากเมาส์ตามเป้าหมาย", time: 10, type: "move" },
    { name: "⌨️ Speed Typer", desc: "พิมพ์คำที่ปรากฏให้ถูกต้อง", type: "type" },
    { name: "🎹 Rhythm Keeper", desc: "กดปุ่มค้างและปล่อยให้ตรงจังหวะ", type: "key_rhythm" },
    { name: "🖋️ Steady Hand", desc: "ลากเมาส์ตามทาง: ห้ามออกนอกกรอบ!", type: "steady_path" }
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
    let count = 0; const keys = ["F", "J", "Space"];
    function next() {
        let k = keys[count];
        cv.innerHTML = `<div style="margin-top:60px"><p>กดค้างจนกว่าจะเต็ม</p><div class="key-hint">${k==="Space"?"⎵":k}</div><div id="keyProg" style="width:0%; height:10px; background:var(--neon); margin:20px auto; border-radius:5px;"></div></div>`;
        let pressing = false, progress = 0, interval = null;
        const down = (e) => {
            let target = k === "Space" ? " " : k.toLowerCase();
            if (e.key.toLowerCase() === target && !pressing) {
                pressing = true;
                interval = setInterval(() => {
                    progress += 2; document.getElementById("keyProg").style.width = progress + "%";
                    if (progress >= 100) {
                        clearInterval(interval); window.removeEventListener("keydown", down); window.removeEventListener("keyup", up);
                        count++; if (count < keys.length) next(); else finishStage();
                    }
                }, 20);
            }
        };
        const up = (e) => { if (e.key.toLowerCase() === (k==="Space"?" ":k.toLowerCase())) { pressing = false; clearInterval(interval); progress = 0; if(document.getElementById("keyProg")) document.getElementById("keyProg").style.width = "0%"; } };
        window.addEventListener("keydown", down); window.addEventListener("keyup", up);
    }
    next();
}

function initSteadyPath(cv) {
    cv.innerHTML = `
        <div class="maze-container">
            <svg width="100%" height="100%" viewBox="0 0 600 360">
                <path class="maze-road" d="M 100 60 H 500 V 180 H 100 V 300 H 500" />
                <path id="mazeTrigger" class="maze-trigger" d="M 100 60 H 500 V 180 H 100 V 300 H 500" />
            </svg>
            <div id="start-node" class="maze-point" style="left:150px; top:60px; background:var(--accent); box-shadow: 0 0 15px var(--accent);">START</div>
            <div id="goal-node" class="maze-point" style="left:580px; top:300px; background:var(--neon); color:#000;">GOAL</div>
        </div>
    `;

    const trig = document.getElementById("mazeTrigger");
    const goal = document.getElementById("goal-node");
    const start = document.getElementById("start-node");
    let isStarted = false;

    // เริ่มเกมเมื่อเมาส์อยู่ที่จุด START
    start.onmouseenter = () => {
        isStarted = true;
        start.style.background = "var(--neon)";
        start.style.boxShadow = "0 0 20px var(--neon)";
        start.innerText = "GO!";
    };

    // ถ้าเมาส์หลุดออกจากเส้นทาง (mazeTrigger)
    trig.onmouseleave = (e) => {
        if (isStarted && e.relatedTarget !== goal) {
            isStarted = false;
            // ทำ Effect กระพริบสีแดงที่จุด Start เพื่อบอกให้กลับไปเริ่มใหม่
            start.style.background = "red";
            start.style.boxShadow = "0 0 30px red";
            start.innerText = "RETRY";
            
            // ใส่ Delay เล็กน้อยก่อนกลับเป็นสีปกติ
            setTimeout(() => {
                start.style.background = "var(--accent)";
                start.style.boxShadow = "0 0 15px var(--accent)";
            }, 500);
        }
    };

    // ชนะเมื่อถึงจุด GOAL และต้องเริ่มมาจากจุด START เท่านั้น
    goal.onmouseenter = () => {
        if (isStarted) {
            isStarted = false;
            trig.onmouseleave = null;
            finishStage();
        }
    };
}

async function autoExportData() {
    const status = document.getElementById("save-status");
    const msg = document.getElementById("final-msg");
    status.innerText = "⏳ กำลังบันทึกข้อมูลแบบ 3-Decimal...";

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
            status.innerText = "✅ บันทึกสำเร็จ (Scaled & 3-Decimal)";
            msg.innerText = "ข้อมูลถูกส่งเข้าระบบเรียบร้อย";
        } else { throw new Error("Server Error"); }
    } catch (err) {
        status.style.color = "var(--accent)";
        status.innerText = "❌ ผิดพลาด: " + err.message;
        msg.innerHTML = `<button class="main-btn" onclick="autoExportData()">ลองใหม่</button>`;
    }
}

renderStage();