/**
 * Hand-rolled Prometheus registry (09 §2 Phase 3 — "observability maturation").
 *
 * No third-party client library on purpose: this process handles a national
 * identity trust chain, so every dependency on the request path is attack
 * surface and supply-chain risk we would have to justify in the pre-prod
 * security gate (06 §8). The text exposition format is small and stable
 * enough to own outright — that is all this file is.
 *
 * PRIVACY IS A CARDINAL CONSTRAINT HERE, not a nicety. A Prometheus label
 * value becomes a permanent, queryable, widely-replicated time series. Put a
 * citizen identifier (raw NID, pseudo-NID, pairwise subject, binding id,
 * nonce) in one and you have simultaneously (a) leaked identity into the
 * monitoring estate, which sits outside the audit trail's access controls
 * (07 §5), and (b) created unbounded cardinality that will eventually take
 * the broker or the scrape target down. Both failure modes are silent until
 * they are catastrophic, so `unsafeLabelReason` below refuses the shapes that
 * identify, and every metric family caps its own series count.
 */

/** Escaping per the Prometheus text exposition format (label values only). */
function escapeLabelValue(value: string): string {
  return value.replace(/\\/g, '\\\\').replace(/\n/g, '\\n').replace(/"/g, '\\"');
}

/** Escaping for HELP text: backslash and newline only. */
function escapeHelp(help: string): string {
  return help.replace(/\\/g, '\\\\').replace(/\n/g, '\\n');
}

export type Labels = Record<string, string>;

/**
 * Shapes a label value must never have. These are exactly the identifiers the
 * broker handles: a raw NID (16 digits), a pseudo-NID or hash (long hex), a
 * uuid (citizen id, binding id, rp row id), and base64url blobs (nonces,
 * challenge ids, auth_req_ids, tokens, pairwise subjects). Rejecting by SHAPE
 * rather than by field name is deliberate: the next person to add a metric
 * will not have read this comment, and a shape check still catches them.
 */
const RAW_NID_SHAPE = /\d{16}/;
const LONG_HEX_SHAPE = /^[0-9a-fA-F]{24,}$/;
const UUID_SHAPE = /^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$/;
/** Enum-ish vocabulary: letters, digits, and the separators our labels use. */
const ALLOWED_CHARS = /^[A-Za-z0-9_.:+/-]+$/;
/** A separator somewhere is what distinguishes a long enum from a token blob. */
const HAS_SEPARATOR = /[_.:+/-]/;
/**
 * …and so does a digit. `getReferenceBiometric` and `SdidTimeoutError` are
 * legitimate long unseparated labels (method and error-class names) and
 * contain no digits; a base64url nonce or id draws from a 64-symbol alphabet
 * and is essentially certain to contain one.
 */
const HAS_DIGIT = /\d/;
const MAX_LABEL_VALUE_LENGTH = 40;
/** At/above this length an unseparated value is treated as high-entropy. */
const BLOB_SUSPICION_LENGTH = 20;

/** Max distinct label-value combinations per metric family (outage guard). */
export const MAX_SERIES_PER_METRIC = 200;

/** Substituted for a label value that fails the identity-shape check. */
export const REJECTED_LABEL_VALUE = '__rejected__';

export class UnsafeLabelValueError extends Error {
  constructor(metric: string, label: string, reason: string) {
    super(`unsafe metric label ${metric}{${label}}: ${reason} — never label a series with an identifier`);
    this.name = 'UnsafeLabelValueError';
  }
}

/**
 * Returns null when the value is safe, else the reason it is not.
 * Exported for unit tests: the rules are a security control, so they are
 * tested directly rather than only through the metrics that use them.
 */
export function unsafeLabelReason(value: string): string | null {
  if (value === '') return null; // absent label on a family that declares it
  if (value.length > MAX_LABEL_VALUE_LENGTH) {
    return `longer than ${MAX_LABEL_VALUE_LENGTH} characters`;
  }
  if (!ALLOWED_CHARS.test(value)) return 'contains characters outside the enum vocabulary';
  if (RAW_NID_SHAPE.test(value)) return 'contains a 16-digit NID-shaped run';
  if (UUID_SHAPE.test(value)) return 'looks like a uuid (citizen/binding/rp identifier)';
  if (LONG_HEX_SHAPE.test(value)) return 'looks like a hash or pseudo-NID';
  if (value.length >= BLOB_SUSPICION_LENGTH && !HAS_SEPARATOR.test(value) && HAS_DIGIT.test(value)) {
    return 'looks like an opaque token/nonce/pairwise subject';
  }
  return null;
}

/**
 * Fail-closed under `strict` — enabled in the TEST environment only, where a
 * mislabelled series should break the build and cost nothing. Everywhere a
 * citizen may be waiting (production AND development/demo) it degrades to a
 * placeholder instead: the observability path must never become a
 * denial-of-service on the authentication path.
 */
function sanitizeLabelValue(metric: string, label: string, value: string, strict: boolean): string {
  const reason = unsafeLabelReason(value);
  if (reason === null) return value;
  if (strict) throw new UnsafeLabelValueError(metric, label, reason);
  return REJECTED_LABEL_VALUE;
}

/**
 * Render a sample value. Float accumulation produces values like
 * `0.0017444739999999998`; six decimals is microsecond resolution on a
 * seconds-scale metric — beyond any operational need — and it keeps the
 * exposition small and free of long digit runs that scanners (ours included)
 * would otherwise have to reason about.
 */
function formatValue(value: number): string {
  if (Number.isInteger(value)) return String(value);
  return String(Number(value.toFixed(6)));
}

function labelKey(labelNames: readonly string[], labels: Labels): string {
  return labelNames.map((n) => labels[n] ?? '').join('\u0000');
}

function renderLabels(labelNames: readonly string[], values: readonly string[]): string {
  if (labelNames.length === 0) return '';
  const parts = labelNames.map((n, i) => `${n}="${escapeLabelValue(values[i] ?? '')}"`);
  return `{${parts.join(',')}}`;
}

abstract class Metric {
  protected readonly series = new Map<string, { values: string[]; state: SeriesState }>();
  /** Set once the family hits MAX_SERIES_PER_METRIC; surfaced as a metric. */
  droppedSeries = 0;

  constructor(
    readonly name: string,
    readonly help: string,
    readonly labelNames: readonly string[],
    private readonly strictLabels: boolean,
  ) {}

  abstract get type(): string;
  protected abstract newState(): SeriesState;

  protected resolve(labels: Labels): SeriesState | null {
    const values = this.labelNames.map((n) =>
      sanitizeLabelValue(this.name, n, labels[n] ?? '', this.strictLabels),
    );
    const key = values.join('\u0000');
    const existing = this.series.get(key);
    if (existing) return existing.state;
    if (this.series.size >= MAX_SERIES_PER_METRIC) {
      // Cardinality ceiling: drop rather than grow without bound. Losing a
      // label combination is an inconvenience; an OOM broker is an outage of
      // a national authentication service.
      this.droppedSeries += 1;
      return null;
    }
    const state = this.newState();
    this.series.set(key, { values, state });
    return state;
  }

  /** Text-exposition lines for this family (no trailing newline). */
  expose(): string[] {
    const lines: string[] = [`# HELP ${this.name} ${escapeHelp(this.help)}`, `# TYPE ${this.name} ${this.type}`];
    for (const { values, state } of this.series.values()) {
      lines.push(...this.exposeSeries(values, state));
    }
    return lines;
  }

  protected abstract exposeSeries(values: readonly string[], state: SeriesState): string[];

  /** Test-only: drop all series so suites do not observe each other's counts. */
  reset(): void {
    this.series.clear();
    this.droppedSeries = 0;
  }
}

interface SeriesState {
  [k: string]: unknown;
}

interface CounterState extends SeriesState {
  value: number;
}

export class Counter extends Metric {
  get type(): string {
    return 'counter';
  }

  protected newState(): CounterState {
    return { value: 0 };
  }

  inc(labels: Labels = {}, amount = 1): void {
    const state = this.resolve(labels) as CounterState | null;
    if (state) state.value += amount;
  }

  /** Test/introspection accessor. Returns 0 for an unobserved combination. */
  get(labels: Labels = {}): number {
    const key = labelKey(this.labelNames, labels);
    return (this.series.get(key)?.state as CounterState | undefined)?.value ?? 0;
  }

  protected exposeSeries(values: readonly string[], state: SeriesState): string[] {
    return [`${this.name}${renderLabels(this.labelNames, values)} ${formatValue((state as CounterState).value)}`];
  }
}

interface GaugeState extends SeriesState {
  value: number;
}

export class Gauge extends Metric {
  get type(): string {
    return 'gauge';
  }

  protected newState(): GaugeState {
    return { value: 0 };
  }

  set(value: number, labels: Labels = {}): void {
    const state = this.resolve(labels) as GaugeState | null;
    if (state) state.value = value;
  }

  inc(labels: Labels = {}, amount = 1): void {
    const state = this.resolve(labels) as GaugeState | null;
    if (state) state.value += amount;
  }

  get(labels: Labels = {}): number {
    const key = labelKey(this.labelNames, labels);
    return (this.series.get(key)?.state as GaugeState | undefined)?.value ?? 0;
  }

  protected exposeSeries(values: readonly string[], state: SeriesState): string[] {
    return [`${this.name}${renderLabels(this.labelNames, values)} ${formatValue((state as GaugeState).value)}`];
  }
}

interface HistogramState extends SeriesState {
  buckets: number[];
  sum: number;
  count: number;
}

/** Latency buckets in SECONDS (Prometheus convention), tuned for SDID calls. */
export const DEFAULT_LATENCY_BUCKETS = [0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10] as const;

export class Histogram extends Metric {
  constructor(
    name: string,
    help: string,
    labelNames: readonly string[],
    strictLabels: boolean,
    readonly buckets: readonly number[] = DEFAULT_LATENCY_BUCKETS,
  ) {
    super(name, help, labelNames, strictLabels);
  }

  get type(): string {
    return 'histogram';
  }

  protected newState(): HistogramState {
    return { buckets: this.buckets.map(() => 0), sum: 0, count: 0 };
  }

  observe(value: number, labels: Labels = {}): void {
    const state = this.resolve(labels) as HistogramState | null;
    if (!state) return;
    state.sum += value;
    state.count += 1;
    for (let i = 0; i < this.buckets.length; i += 1) {
      if (value <= (this.buckets[i] as number)) state.buckets[i] = (state.buckets[i] as number) + 1;
    }
  }

  get(labels: Labels = {}): { count: number; sum: number } {
    const key = labelKey(this.labelNames, labels);
    const state = this.series.get(key)?.state as HistogramState | undefined;
    return { count: state?.count ?? 0, sum: state?.sum ?? 0 };
  }

  protected exposeSeries(values: readonly string[], state: SeriesState): string[] {
    const h = state as HistogramState;
    const lines: string[] = [];
    // Buckets are CUMULATIVE and must be emitted in ascending order, ending
    // with +Inf == count; a scraper rejects the family otherwise.
    for (let i = 0; i < this.buckets.length; i += 1) {
      const le = String(this.buckets[i]);
      lines.push(
        `${this.name}_bucket${renderLabels([...this.labelNames, 'le'], [...values, le])} ${h.buckets[i]}`,
      );
    }
    lines.push(
      `${this.name}_bucket${renderLabels([...this.labelNames, 'le'], [...values, '+Inf'])} ${h.count}`,
    );
    lines.push(`${this.name}_sum${renderLabels(this.labelNames, values)} ${formatValue(h.sum)}`);
    lines.push(`${this.name}_count${renderLabels(this.labelNames, values)} ${h.count}`);
    return lines;
  }
}

/**
 * A registry of metric families. One instance lives in MetricsService; the
 * class is standalone (no Nest decorators) so it is unit-testable on its own.
 */
export class MetricsRegistry {
  private readonly metrics = new Map<string, Metric>();

  /**
   * `strictLabels` throws on an identifying label value instead of substituting
   * a placeholder. On in development/test, off in production (see
   * `sanitizeLabelValue`).
   */
  constructor(private readonly strictLabels: boolean) {}

  counter(name: string, help: string, labelNames: readonly string[] = []): Counter {
    return this.register(new Counter(name, help, labelNames, this.strictLabels));
  }

  gauge(name: string, help: string, labelNames: readonly string[] = []): Gauge {
    return this.register(new Gauge(name, help, labelNames, this.strictLabels));
  }

  histogram(
    name: string,
    help: string,
    labelNames: readonly string[] = [],
    buckets: readonly number[] = DEFAULT_LATENCY_BUCKETS,
  ): Histogram {
    return this.register(new Histogram(name, help, labelNames, this.strictLabels, buckets));
  }

  private register<T extends Metric>(metric: T): T {
    if (this.metrics.has(metric.name)) {
      throw new Error(`metric ${metric.name} is already registered`);
    }
    this.metrics.set(metric.name, metric);
    return metric;
  }

  /** Total label combinations dropped at the cardinality ceiling. */
  droppedSeries(): number {
    let total = 0;
    for (const m of this.metrics.values()) total += m.droppedSeries;
    return total;
  }

  /** Full text exposition. Families are emitted in registration order. */
  render(): string {
    const lines: string[] = [];
    for (const metric of this.metrics.values()) lines.push(...metric.expose());
    return `${lines.join('\n')}\n`;
  }

  /** Test-only: clear every family's series. */
  resetForTest(): void {
    for (const metric of this.metrics.values()) metric.reset();
  }
}
