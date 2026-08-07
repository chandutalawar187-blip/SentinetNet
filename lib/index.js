const { spawn } = require('child_process');
const fs = require('fs');
const path = require('path');
const EventEmitter = require('events');

class Sentinet extends EventEmitter {
  constructor(opts = {}) {
    super();
    this.pythonPath = opts.pythonPath || 'python';
    this.script = opts.script || path.join(__dirname, '..', 'backend', 'capture.py');
    this.iface = opts.iface || process.env.SENTINET_INTERFACE || null;
    this.proc = null;
    this.alertFile = path.join(__dirname, '..', 'shared', 'alerts.json');
    this.alertJsonl = path.join(__dirname, '..', 'shared', 'alerts.jsonl');
    this._watcher = null;
  }

  start() {
    if (this.proc) return;
    const args = [this.script];
    if (this.iface) args.unshift('--iface', this.iface);
    this.proc = spawn(this.pythonPath, args, { stdio: ['ignore', 'pipe', 'pipe'] });
    this.proc.stdout.on('data', (d) => {
      const s = d.toString();
      this.emit('stdout', s);
    });
    this.proc.stderr.on('data', (d) => {
      const s = d.toString();
      this.emit('stderr', s);
    });
    this.proc.on('exit', (code) => {
      this.emit('exit', code);
      this.proc = null;
      if (this._watcher) {
        try { this._watcher.close(); } catch(e){}
        this._watcher = null;
      }
    });

    const fileToWatch = fs.existsSync(this.alertJsonl) ? this.alertJsonl : this.alertFile;
    try {
      this._watcher = fs.watch(fileToWatch, { encoding: 'utf8' }, (event) => {
        if (event === 'change' || event === 'rename') {
          this._emitLatestAlert();
        }
      });
      setTimeout(() => this._emitLatestAlert(), 500);
    } catch (e) {
      // ignore
    }
  }

  _emitLatestAlert() {
    if (fs.existsSync(this.alertJsonl)) {
      try {
        const data = fs.readFileSync(this.alertJsonl, 'utf8').trim().split('\n');
        if (data.length) {
          const last = data[data.length - 1];
          const obj = JSON.parse(last);
          this.emit('alert', obj);
        }
      } catch (e) {
      }
    } else if (fs.existsSync(this.alertFile)) {
      try {
        const arr = JSON.parse(fs.readFileSync(this.alertFile, 'utf8'));
        if (Array.isArray(arr) && arr.length) {
          this.emit('alert', arr[arr.length - 1]);
        }
      } catch (e) {}
    }
  }

  stop() {
    if (!this.proc) return;
    try { this.proc.kill(); } catch(e){}
    this.proc = null;
  }

  tailAlerts(n = 10) {
    if (fs.existsSync(this.alertJsonl)) {
      const lines = fs.readFileSync(this.alertJsonl, 'utf8').trim().split('\n');
      return lines.slice(-n).map(l => { try { return JSON.parse(l); } catch(e){ return null; } }).filter(Boolean);
    }
    if (fs.existsSync(this.alertFile)) {
      try {
        const arr = JSON.parse(fs.readFileSync(this.alertFile, 'utf8'));
        return arr.slice(-n);
      } catch (e) { return []; }
    }
    return [];
  }
}

module.exports = Sentinet;
