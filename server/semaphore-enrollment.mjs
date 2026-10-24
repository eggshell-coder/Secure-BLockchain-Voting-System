import { randomInt } from "node:crypto";

export function shuffleCommitments(commitments, draw = randomInt) {
  if (!Array.isArray(commitments) || commitments.some((value) =>
    typeof value !== "string" || !/^[1-9][0-9]{0,76}$/.test(value)
  ) || new Set(commitments).size !== commitments.length) {
    throw new TypeError("Expected unique canonical Semaphore commitments.");
  }
  const shuffled = [...commitments];
  for (let index = shuffled.length - 1; index > 0; index -= 1) {
    const selected = draw(index + 1);
    if (!Number.isSafeInteger(selected) || selected < 0 || selected > index) {
      throw new RangeError("Random source returned an invalid shuffle index.");
    }
    [shuffled[index], shuffled[selected]] = [shuffled[selected], shuffled[index]];
  }
  return shuffled;
}
