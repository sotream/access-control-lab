import { crc32 } from "node:zlib";

/** Small valid files for tests (shared by the unit tests here and the database/API tests). */
const chunk = (type: string, data: Buffer): Buffer => {
  const len = Buffer.alloc(4);
  len.writeUInt32BE(data.length);
  const body = Buffer.concat([Buffer.from(type, "latin1"), data]);
  const crc = Buffer.alloc(4);
  crc.writeUInt32BE(crc32(body));
  return Buffer.concat([len, body, crc]);
};

export function makePng(w = 2, h = 2, extra: Buffer = Buffer.alloc(0)): Buffer {
  const ihdr = Buffer.alloc(13);
  ihdr.writeUInt32BE(w, 0);
  ihdr.writeUInt32BE(h, 4);
  ihdr.set([8, 2, 0, 0, 0], 8);
  return Buffer.concat([Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]), chunk("IHDR", ihdr), chunk("IDAT", Buffer.from([0x78, 0x9c, 0x63, 0x00, 0x00, 0x00, 0x02, 0x00, 0x01])), chunk("IEND", Buffer.alloc(0)), extra]);
}

export const makeJpeg = (): Buffer => Buffer.concat([Buffer.from([0xff, 0xd8, 0xff, 0xe0]), Buffer.alloc(140, 0x41), Buffer.from([0xff, 0xd9])]);
export const makePdf = (body = ""): Buffer => Buffer.from(`%PDF-1.7\n1 0 obj\n<< /Type /Catalog >>\nendobj\n${body}\ntrailer\n<< /Root 1 0 R >>\n%%EOF\n`, "latin1");
export const makeText = (s = "plain notes\nsecond line\n"): Buffer => Buffer.from(s, "utf8");
