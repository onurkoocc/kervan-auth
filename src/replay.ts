/** Remembers used assertion `jti`s until their assertion has expired, so each is accepted once. */
export class JtiCache {
  private readonly seen = new Map<string, number>();

  /** Records `key` as used until `expiresAtSec`; false when it was already used. */
  use(key: string, expiresAtSec: number, nowSec: number): boolean {
    this.prune(nowSec);
    if (this.seen.has(key)) return false;
    this.seen.set(key, expiresAtSec);
    return true;
  }

  private prune(nowSec: number): void {
    for (const [key, exp] of this.seen) {
      if (exp < nowSec) this.seen.delete(key);
    }
  }
}
