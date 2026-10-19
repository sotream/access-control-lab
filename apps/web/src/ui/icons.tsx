// One inline SVG set, hand-drawn on a 24 px grid (stroke icons, currentColor). No icon font, no sprite file, no remote request: the markup is
// in the page, so the CSP (img-src 'self' data:) is untouched. Icons are decoration next to a text label, hence aria-hidden.
const PATHS = {
  shield: "M12 3 5 6v5.5c0 4.3 2.8 7.6 7 9.5 4.2-1.9 7-5.2 7-9.5V6l-7-3Zm-3 8.5 2.2 2.2L15.5 9.4",
  home: "M4 11 12 4l8 7v8a1 1 0 0 1-1 1h-4v-6H9v6H5a1 1 0 0 1-1-1v-8Z",
  folder: "M3.5 7.5V6a1 1 0 0 1 1-1h4.2l2 2h8.8a1 1 0 0 1 1 1v10a1 1 0 0 1-1 1h-15a1 1 0 0 1-1-1V7.5Z",
  plus: "M12 5v14M5 12h14",
  inbox: "M4 13h4l1.5 2.5h5L16 13h4M4 13l2-7h12l2 7v5a1 1 0 0 1-1 1H5a1 1 0 0 1-1-1v-5Z",
  alert: "M12 4 3 19.5h18L12 4Zm0 6v4.5m0 2.5v.01",
  list: "M8 6h12M8 12h12M8 18h12M4 6h.01M4 12h.01M4 18h.01",
  verify: "M12 3 5 6v5.5c0 4.3 2.8 7.6 7 9.5 4.2-1.9 7-5.2 7-9.5V6l-7-3Zm-3.2 9 2.4 2.4 4.2-4.8",
  user: "M12 12a4 4 0 1 0 0-8 4 4 0 0 0 0 8Zm-7 8c.6-3.4 3.4-5.5 7-5.5s6.4 2.1 7 5.5",
  logout: "M10 5H6a1 1 0 0 0-1 1v12a1 1 0 0 0 1 1h4M15 8l4 4-4 4M19 12H9",
  lock: "M6 11h12v8a1 1 0 0 1-1 1H7a1 1 0 0 1-1-1v-8Zm2 0V8a4 4 0 0 1 8 0v3",
  key: "M14.5 9.5a4 4 0 1 1-1.2 2.8L4 21.5V19l2-.5V16.5l2-.5L12 12l2.5-2.5Z",
  paperclip: "M18.5 11.5 11 19a4.5 4.5 0 0 1-6.4-6.4l8-8a3 3 0 0 1 4.3 4.3l-8 8a1.5 1.5 0 0 1-2.1-2.1l7-7",
  download: "M12 4v11m0 0-4-4m4 4 4-4M5 20h14",
  check: "m5 12.5 4.5 4.5L19 7.5",
  x: "m6 6 12 12M18 6 6 18",
  clock: "M12 21a9 9 0 1 0 0-18 9 9 0 0 0 0 18Zm0-13.5V12l3 2",
  eye: "M2.5 12S6 5.5 12 5.5 21.5 12 21.5 12 18 18.5 12 18.5 2.5 12 2.5 12Zm9.5 3a3 3 0 1 0 0-6 3 3 0 0 0 0 6Z",
  edit: "M4 20h4L19 9a2.1 2.1 0 0 0-3-3L5 17v3Zm9-13 3 3",
  send: "m21 3-9.5 9.5M21 3l-6.5 18-3-8.5L3 9.5 21 3Z",
  trash: "M5 7h14M10 7V5h4v2m-7 0 1 12h8l1-12M10 11v5m4-5v5",
  search: "M11 18a7 7 0 1 0 0-14 7 7 0 0 0 0 14Zm5-2 4 4",
  export: "M12 15V4m0 0L8 8m4-4 4 4M5 14v5a1 1 0 0 0 1 1h12a1 1 0 0 0 1-1v-5",
  info: "M12 21a9 9 0 1 0 0-18 9 9 0 0 0 0 18Zm0-10v5m0-8v.01",
  file: "M7 3h7l5 5v12a1 1 0 0 1-1 1H7a1 1 0 0 1-1-1V4a1 1 0 0 1 1-1Zm7 0v5h5",
} as const;

export type IconName = keyof typeof PATHS;

export function Icon({ name }: { name: IconName }) {
  return (
    <svg className="icon" viewBox="0 0 24 24" aria-hidden="true" focusable="false">
      <path d={PATHS[name]} />
    </svg>
  );
}
