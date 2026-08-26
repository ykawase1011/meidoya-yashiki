export interface Clock {
  now(): Date;
}

export const systemClock: Clock = {
  now: () => new Date(),
};

export function fixedClock(iso: string): Clock {
  return { now: () => new Date(iso) };
}

export type LogLevel = "debug" | "info" | "warn" | "error";

export interface Logger {
  log(level: LogLevel, message: string, fields?: Readonly<Record<string, string | number | boolean>>): void;
}

export const silentLogger: Logger = {
  log: () => undefined,
};

export function createConsoleLogger(write: (line: string) => void = (line) => process.stderr.write(`${line}\n`)): Logger {
  return {
    log: (level, message, fields) => {
      const suffix =
        fields === undefined || Object.keys(fields).length === 0
          ? ""
          : ` ${Object.entries(fields)
              .map(([key, value]) => `${key}=${String(value)}`)
              .join(" ")}`;
      write(`[${level}] ${message}${suffix}`);
    },
  };
}

/** Records every log line so tests can assert that no secret ever reaches a sink. */
export function createRecordingLogger(): Logger & { readonly lines: readonly string[] } {
  const lines: string[] = [];
  return {
    lines,
    log: (level, message, fields) => {
      lines.push(`${level} ${message} ${JSON.stringify(fields ?? {})}`);
    },
  };
}
