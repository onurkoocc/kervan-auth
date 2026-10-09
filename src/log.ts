import { appendFileSync, mkdirSync } from "node:fs";
import { dirname } from "node:path";

/** JSON-lines logging (SPEC §6). Callers never pass secrets, assertions or tokens. */
export type Level = "info" | "warn" | "error";
export type Fields = Record<string, string | number | boolean | undefined>;

export interface Logger {
  log(level: Level, msg: string, fields?: Fields): void;
}

export type Sink = (line: string) => void;

const SERVICE = "auth";

export function formatLine(level: Level, msg: string, fields: Fields = {}, now = new Date()): string {
  const entry: Record<string, unknown> = { ts: now.toISOString(), level, service: SERVICE, msg };
  for (const [k, v] of Object.entries(fields)) {
    if (v !== undefined && !(k in entry)) entry[k] = v;
  }
  return JSON.stringify(entry);
}

export function createLogger(sinks: Sink[]): Logger {
  return {
    log(level, msg, fields) {
      const line = formatLine(level, msg, fields);
      for (const sink of sinks) sink(line);
    },
  };
}

export function stdoutSink(): Sink {
  return (line) => {
    process.stdout.write(line + "\n");
  };
}

/** Appends to `path`; a failing file never takes the service down, it is reported once on stderr. */
export function fileSink(path: string): Sink {
  let failed = false;
  try {
    mkdirSync(dirname(path), { recursive: true });
  } catch {
    // appendFileSync below reports the problem.
  }
  return (line) => {
    if (failed) return;
    try {
      appendFileSync(path, line + "\n");
    } catch (err) {
      failed = true;
      process.stderr.write(
        formatLine("error", "log file not writable; logging to stdout only", {
          log_file: path,
          reason: err instanceof Error ? err.message : String(err),
        }) + "\n",
      );
    }
  };
}
