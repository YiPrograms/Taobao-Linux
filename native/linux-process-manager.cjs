// Linux implementation of the non-security Windows working-set helper.
// optimizeProcessMemory cannot emulate EmptyWorkingSet safely, so returns false.
'use strict';

const fs = require('node:fs');
const os = require('node:os');

function isProcessRunning(pid) {
  if (!Number.isInteger(pid) || pid <= 0) return false;
  try {
    process.kill(pid, 0);
    return true;
  } catch (err) {
    return err.code === 'EPERM';
  }
}

function getProcessMemoryUsage(pid) {
  if (!Number.isInteger(pid) || pid <= 0) throw new TypeError('Expected positive PID');
  const status = fs.readFileSync(`/proc/${pid}/status`, 'utf8');
  const match = status.match(/^VmRSS:\s+(\d+)\s+kB$/m);
  return match ? Number(match[1]) : 0;
}

class ProcessManager {
  optimizeProcessMemory(pid) {
    if (!Number.isInteger(pid) || pid <= 0) throw new TypeError('Expected positive PID');
    return false;
  }

  optimizeCurrentProcess() {
    return this.optimizeProcessMemory(process.pid);
  }
  getProcessMemoryUsage(pid) {
    return getProcessMemoryUsage(pid);
  }
  isProcessRunning(pid) {
    return isProcessRunning(pid);
  }

  getSystemMemoryStatus() {
    const totalPhysical = os.totalmem();
    const availablePhysical = os.freemem();
    return {
      totalPhysical,
      availablePhysical,
      memoryLoad: Math.round((1 - availablePhysical / totalPhysical) * 100),
    };
  }

  optimizeMultipleProcesses(pids) {
    return Object.fromEntries(
      pids.map((pid) => [pid, { success: this.optimizeProcessMemory(pid), error: null }]),
    );
  }

  getMemoryReport(pid) {
    const memoryUsage = this.getProcessMemoryUsage(pid);
    const systemStatus = this.getSystemMemoryStatus();
    return {
      pid,
      memoryUsage,
      memoryUsageMB: (memoryUsage / 1024).toFixed(2),
      isRunning: this.isProcessRunning(pid),
      systemMemory: {
        totalPhysical: `${(systemStatus.totalPhysical / 1024 / 1024).toFixed(2)} MB`,
        availablePhysical: `${(systemStatus.availablePhysical / 1024 / 1024).toFixed(2)} MB`,
        memoryLoad: `${systemStatus.memoryLoad}%`,
      },
    };
  }
}

module.exports = ProcessManager;
module.exports.ProcessManager = ProcessManager;
