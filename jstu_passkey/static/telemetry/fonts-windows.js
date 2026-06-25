import { detectFontList } from "./font-detect.js";

const WINDOWS_FONTS = [
  "Segoe UI",
  "Calibri",
  "Cambria",
  "Consolas",
  "Arial",
  "Times New Roman",
];

export function detectFonts() {
  return detectFontList(WINDOWS_FONTS);
}
