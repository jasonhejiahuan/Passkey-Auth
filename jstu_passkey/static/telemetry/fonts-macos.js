import { detectFontList } from "./font-detect.js";

const APPLE_FONTS = [
  "Helvetica Neue",
  "Menlo",
  "Monaco",
  "Avenir Next",
  "Arial",
  "Times",
];

export function detectFonts() {
  return detectFontList(APPLE_FONTS);
}
