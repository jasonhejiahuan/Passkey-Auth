import { detectFontList } from "./font-detect.js";

const LINUX_FONTS = [
  "DejaVu Sans",
  "Liberation Sans",
  "Ubuntu",
  "Cantarell",
  "Noto Sans",
  "Noto Mono",
];

export function detectFonts() {
  return detectFontList(LINUX_FONTS);
}
