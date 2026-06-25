const BASE_FONTS = ["monospace", "sans-serif", "serif"];
const TEST_TEXT = "mmmmmmmmmmlli";

export function detectFontList(candidates) {
  if (!document.body) return [];
  const canvas = document.createElement("canvas");
  const context = canvas.getContext("2d");
  if (!context) return [];
  context.font = `72px ${BASE_FONTS[0]}`;
  const baselines = Object.fromEntries(
    BASE_FONTS.map((font) => {
      context.font = `72px ${font}`;
      return [font, context.measureText(TEST_TEXT).width];
    }),
  );
  return candidates.filter((candidate) => BASE_FONTS.some((fallback) => {
    context.font = `72px "${candidate}", ${fallback}`;
    return context.measureText(TEST_TEXT).width !== baselines[fallback];
  }));
}
