import { describe, expect, it } from "vitest";
import { getProgramId } from "../src/uploadStats";

describe("upload statistics program identity", () => {
  it("uses the executable path as the stable program identity", () => {
    expect(getProgramId({ executable: " /Applications/Uploader.app ", name: "Uploader" })).toBe("/Applications/Uploader.app");
  });

  it("falls back to the process name when an executable is unavailable", () => {
    expect(getProgramId({ executable: "", name: "Uploader" })).toBe("Uploader");
  });

  it("trims both fields before using the fallback", () => {
    expect(getProgramId({ executable: "  ", name: "  worker  " })).toBe("worker");
  });
});
