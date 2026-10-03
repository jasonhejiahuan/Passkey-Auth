/** All multi-statement changes use D1 batch, whose failure rolls back every step. */
export class StoreConflict extends Error {
  constructor(
    message = "Authorization changed or this operation was already used",
  ) {
    super(message);
    this.name = "StoreConflict";
  }
}

export class Store {
  constructor(public db: D1Database) {}

  one<T = Record<string, unknown>>(
    sql: string,
    ...bindings: unknown[]
  ): Promise<T | null> {
    return this.db
      .prepare(sql)
      .bind(...bindings)
      .first<T>();
  }

  async all<T = Record<string, unknown>>(
    sql: string,
    ...bindings: unknown[]
  ): Promise<T[]> {
    const result = await this.db
      .prepare(sql)
      .bind(...bindings)
      .all<T>();
    return result.results;
  }

  run(sql: string, ...bindings: unknown[]): Promise<D1Result> {
    return this.db
      .prepare(sql)
      .bind(...bindings)
      .run();
  }

  batch(statements: D1PreparedStatement[]): Promise<D1Result[]> {
    if (statements.length === 0) return Promise.resolve([]);
    return this.db.batch(statements);
  }

  /**
   * conditionSql is a server-authored SQL expression, never request text.
   * It is evaluated inside the same transaction as all of the supplied writes.
   * Returned results correspond only to the supplied statements.
   * A rejected guard or any failed write preserves the previous action token.
   */
  async guardBatch(
    conditionSql: string,
    conditionBindings: unknown[],
    statements: D1PreparedStatement[],
  ): Promise<D1Result[]> {
    const receipt = crypto.randomUUID();
    try {
      const results = await this.db.batch([
        this.db
          .prepare(
            `INSERT INTO operation_guards (id, allowed) VALUES (?, CASE WHEN (${conditionSql}) THEN 1 ELSE 0 END)`,
          )
          .bind(receipt, ...conditionBindings),
        ...statements,
        this.db
          .prepare("DELETE FROM operation_guards WHERE id = ?")
          .bind(receipt),
      ]);
      return results.slice(1, -1);
    } catch (error) {
      if (
        error instanceof Error &&
        error.message.includes("operation_authorized")
      ) {
        throw new StoreConflict();
      }
      throw error;
    }
  }
}
