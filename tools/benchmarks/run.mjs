import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { mkdirSync, mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { arch, cpus, platform, release } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const bench = dirname(fileURLToPath(import.meta.url));
const root = resolve(bench, '../..');
const storage = join(root, '.abc', 'benchmarks');
const core = 'src/crypto/hash/sha256/impl/rust/src/lib.rs';
const profile = {
  optLevel: 3, codegenUnits: 1, lto: 'off', incremental: false, debug: false, panic: 'unwind',
};
const toolchain = '+1.92.0';
const windows = platform() === 'win32';
const linkerProgram = windows ? 'link.exe' : 'cc';
const rustFlags = ['-Ctarget-cpu=generic', `-Clinker=${linkerProgram}`];
const bootstrapSeed = 4761;
const bootstrapDraws = 2000;

function command(program, args, report, environment = process.env, accepted = [0]) {
  const result = spawnSync(program, args, {
    cwd: root, encoding: 'utf8', timeout: 120_000, maxBuffer: 8 * 1024 * 1024, env: environment,
  });
  writeFileSync(report, `${JSON.stringify([program, ...args])}\n${result.stdout ?? ''}${result.stderr ?? ''}${result.error ?? ''}`);
  if (!accepted.includes(result.status) || result.error) {
    throw new Error(`${program} failed (${result.error?.message ?? result.status})`);
  }
  return result.stdout;
}

function cpuSnapshot() {
  return cpus().reduce((result, cpu) => {
    const total = Object.values(cpu.times).reduce((sum, time) => sum + time, 0);
    return { total: result.total + total, idle: result.idle + cpu.times.idle };
  }, { total: 0, idle: 0 });
}

function powerPolicy() {
  if (windows) {
    return spawnSync('powercfg.exe', ['/GETACTIVESCHEME'], { encoding: 'utf8', timeout: 5000 }).stdout?.trim() || null;
  }
  if (platform() === 'linux') {
    try {
      return readFileSync('/sys/devices/system/cpu/cpu0/cpufreq/scaling_governor', 'utf8').trim() || null;
    } catch {
      return null;
    }
  }
  return null;
}

function sha256(path) {
  return createHash('sha256').update(readFileSync(path)).digest('hex');
}

function percentile(sorted, quantile) {
  const index = (sorted.length - 1) * quantile;
  const lower = Math.floor(index);
  return sorted[lower] + (sorted[Math.ceil(index)] - sorted[lower]) * (index - lower);
}

function summarize(values) {
  const sort = (samples) => samples.sort((a, b) => a - b);
  let state = bootstrapSeed;
  const medians = sort(Array.from({ length: bootstrapDraws }, () => {
    const resample = Array.from({ length: values.length }, () => {
      state = (Math.imul(state, 1664525) + 1013904223) >>> 0;
      return values[Math.floor(state / 2 ** 32 * values.length)];
    });
    return percentile(sort(resample), 0.5);
  }));
  const sorted = sort([...values]);
  return {
    median: percentile(sorted, 0.5),
    min: sorted[0],
    max: sorted.at(-1),
    bootstrap95: [percentile(medians, 0.025), percentile(medians, 0.975)],
  };
}

function measurements(output) {
  const [header, ...lines] = output.trim().split(/\r?\n/);
  const [format, ...parameters] = header.split('\t');
  const [inputPool, warmupBatches, rounds, seed] = parameters.map(Number);
  if (format !== 'abc-benchmark-v1' || parameters.length !== 4 || !parameters.every((value) => /^[1-9]\d*$/.test(value))) {
    throw new Error('Benchmark returned an invalid measurement header');
  }
  const cases = new Map();
  for (const line of lines) {
    const tokens = line.split('\t');
    const [round, size, iterations, elapsedNs] = tokens.map(Number);
    if (tokens.length !== 4 || !tokens.every((value) => /^\d+$/.test(value)) ||
        !tokens.map(Number).every(Number.isSafeInteger) || round >= rounds || iterations <= 0 || elapsedNs <= 0) {
      throw new Error('Benchmark returned an invalid sample');
    }
    if (!cases.has(size)) cases.set(size, { iterations, samples: new Map() });
    const current = cases.get(size);
    if (current.iterations !== iterations || current.samples.has(round)) throw new Error('Inconsistent benchmark batch');
    current.samples.set(round, elapsedNs);
  }
  if (!cases.size || [...cases.values()].some((item) => item.samples.size !== rounds)) {
    throw new Error('Benchmark returned an incomplete size/round matrix');
  }
  const sizes = [...cases].sort(([a], [b]) => a - b).map(([size, item]) => {
    const elapsedNs = Array.from({ length: rounds }, (_, round) => item.samples.get(round));
    const nsPerOperation = summarize(elapsedNs.map((ns) => ns / item.iterations));
    return { bytes: size, iterations: item.iterations, elapsedNs, nsPerOperation,
      medianMiBPerSecond: size ? size * 1e9 / nsPerOperation.median / 2 ** 20 : null };
  });
  return { inputPool, warmupBatches, rounds, seed, sizes };
}

mkdirSync(storage, { recursive: true });
const work = mkdtempSync(join(storage, 'run-'));
try {
  const targetDir = join(work, 'build');
  const compiler = command('rustc', [toolchain, '-Vv'], join(work, 'rustc.log')).trim();
  const cargo = command('cargo', [toolchain, '-V'], join(work, 'cargo.log')).trim();
  const linker = command(linkerProgram, [windows ? '/?' : '--version'], join(work, 'linker.log'),
    process.env, windows ? [0, 1100] : [0]).trim().split(/\r?\n/)[0];
  if (windows && !/Incremental Linker Version \d+/.test(linker)) throw new Error('Unable to identify the MSVC linker');
  const target = /^host: (\S+)$/m.exec(compiler)?.[1];
  if (!target) throw new Error('Unable to identify the Rust host target');
  const args = [toolchain, 'build', '--release', '--locked', '--offline', '--manifest-path',
    'tools/benchmarks/Cargo.toml', '--target', target, '--target-dir', targetDir];
  const buildEnvironment = Object.fromEntries(Object.entries(process.env).filter(([name]) =>
    !/^CARGO_PROFILE_RELEASE_|^RUSTFLAGS$|^RUSTC(?:$|_WRAPPER$|_WORKSPACE_WRAPPER$)/i.test(name)));
  buildEnvironment.CARGO_ENCODED_RUSTFLAGS = rustFlags.join('\x1f');
  command('cargo', args, join(work, 'build.log'), buildEnvironment);
  const binary = join(targetDir, target, 'release', windows ? 'abc-benchmark.exe' : 'abc-benchmark');
  const policy = powerPolicy();
  const before = cpuSnapshot();
  const data = measurements(command(binary, [], join(work, 'measurements.log')));
  const after = cpuSnapshot();
  const total = after.total - before.total;
  const utilization = total > 0 ? Math.max(0, Math.min(1, 1 - (after.idle - before.idle) / total)) : null;
  const hardware = cpus();
  const result = {
    schemaVersion: 1,
    implementation: 'sha256-abc-rust-portable',
    scope: 'public-input one-shot SHA-256',
    environment: {
      hostTimeUtc: new Date().toISOString(), os: platform(), osRelease: release(), architecture: arch(),
      cpuModel: hardware[0]?.model ?? null, reportedMHz: hardware[0]?.speed ?? null,
      logicalCpus: hardware.length, powerPolicy: policy, aggregateCpuUtilization: utilization,
      isolation: 'shared-workstation-or-ci', affinity: 'inherited',
    },
    build: { compiler, cargo, linker, target, profile, rustFlags, command: ['cargo', ...args], executableSha256: sha256(binary) },
    sourceDigests: Object.fromEntries([core, core.replace('/src/lib.rs', '/Cargo.toml'), 'tools/benchmarks/src/main.rs',
      'tools/benchmarks/Cargo.toml', 'tools/benchmarks/Cargo.lock', 'tools/benchmarks/result.schema.json', 'tools/benchmarks/run.mjs']
      .map((path) => [path, sha256(join(root, path))])),
    method: {
      clock: 'Rust Instant', inputDistribution: 'deterministic xorshift64 low byte',
      sampling: 'rotating size order, warmed and reused input pool', interval: 'percentile bootstrap of batch medians',
      bootstrapSeed, bootstrapDraws, inputPool: data.inputPool, warmupBatches: data.warmupBatches,
      rounds: data.rounds, seed: data.seed,
    },
    sizes: data.sizes,
  };
  writeFileSync(join(work, 'result.json'), `${JSON.stringify(result, null, 2)}\n`);
  console.log(JSON.stringify({ result: join(work, 'result.json'), environment: result.environment,
    sizes: result.sizes.map(({ elapsedNs: _, ...summary }) => summary) }));
} catch (error) {
  console.error(JSON.stringify({ status: 'not_passed', error: error.message, logs: work }));
  process.exitCode = 1;
}
