// Certificate lookup — runs entirely in the browser (no backend).
// data.json holds one AES-GCM encrypted record per phone number; see tools/build-data.mjs.

const CERT = {
  src: 'assets/certificate.jpg',
  width: 2380,               // the exported A4 page at 288 dpi
  height: 3368,
  nameRight: 2160,           // right edge of the name, aligned with "تشهد شركة سول ..." above it
  baseline: 1503,            // baseline of the original "[اسم المشارك/ـة]" placeholder
  fontSize: 116,             // 29 pt at 288 dpi, as in the PowerPoint template
  minLeft: 800,              // keep clear of the tower illustration on the left
  color: '#444DFD',
  font: 'Bahij',
};
const PAGE_PT = { w: 595.28, h: 841.89 }; // A4

const $ = id => document.getElementById(id);
const form = $('lookup'), input = $('phone'), msg = $('phone-msg'), submit = $('submit');
const result = $('result'), nameEl = $('name'), preview = $('preview');
const dlPdf = $('dl-pdf'), dlImg = $('dl-img'), again = $('again');

const enc = new TextEncoder();
const objectUrls = [];

// Start loading everything the certificate needs while the visitor types.
const dataPromise = fetch('data.json', { cache: 'no-cache' }).then(r => {
  if (!r.ok) throw new Error('data ' + r.status);
  return r.json();
});
const imagePromise = new Promise((resolve, reject) => {
  const img = new Image();
  img.onload = () => resolve(img);
  img.onerror = () => reject(new Error('certificate image'));
  img.src = CERT.src;
});
const fontPromise = document.fonts.load(`700 ${CERT.fontSize}px ${CERT.font}`, 'شهادة');
dataPromise.catch(() => {}); imagePromise.catch(() => {}); fontPromise.catch(() => {});

// Same rules as normalizePhone() in tools/build-data.mjs.
function normalizePhone(raw) {
  let d = String(raw)
    .replace(/[٠-٩]/g, c => String(c.charCodeAt(0) - 0x0660))
    .replace(/[۰-۹]/g, c => String(c.charCodeAt(0) - 0x06f0))
    .replace(/\D/g, '');
  if (d.startsWith('00966')) d = d.slice(5);
  else if (d.startsWith('966')) d = d.slice(3);
  if (d.length === 9 && d.startsWith('5')) d = '0' + d;
  return /^05\d{8}$/.test(d) ? d : null;
}

const fromB64 = s => Uint8Array.from(atob(s), c => c.charCodeAt(0));
const toHex = bytes => Array.from(bytes, b => b.toString(16).padStart(2, '0')).join('');

async function findName(phone, data) {
  const base = await crypto.subtle.importKey('raw', enc.encode(phone), 'PBKDF2', false, ['deriveBits']);
  const bits = new Uint8Array(await crypto.subtle.deriveBits(
    { name: 'PBKDF2', hash: 'SHA-256', salt: fromB64(data.salt), iterations: data.iterations }, base, 384));
  const record = data.records[toHex(bits.slice(0, 16))];
  if (!record) return null;
  const blob = fromB64(record);
  const key = await crypto.subtle.importKey('raw', bits.slice(16, 48), 'AES-GCM', false, ['decrypt']);
  const plain = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: blob.slice(0, 12) }, key, blob.slice(12));
  return JSON.parse(new TextDecoder().decode(plain)).n;
}

function drawCertificate(img, name) {
  const canvas = document.createElement('canvas');
  canvas.width = CERT.width;
  canvas.height = CERT.height;
  const ctx = canvas.getContext('2d');
  ctx.drawImage(img, 0, 0, CERT.width, CERT.height);

  ctx.direction = 'rtl';
  ctx.textAlign = 'right';
  ctx.textBaseline = 'alphabetic';
  ctx.fillStyle = CERT.color;
  let size = CERT.fontSize;
  ctx.font = `700 ${size}px ${CERT.font}`;
  const maxWidth = CERT.nameRight - CERT.minLeft;
  const width = ctx.measureText(name).width;
  let baseline = CERT.baseline;
  if (width > maxWidth) {
    // Shrink long names to fit, keeping them centred on the original line.
    size = Math.floor(size * maxWidth / width);
    ctx.font = `700 ${size}px ${CERT.font}`;
    baseline -= Math.round((CERT.fontSize - size) * 0.35);
  }
  ctx.fillText(name, CERT.nameRight, baseline);
  return canvas;
}

const canvasToBlob = (canvas, type, quality) =>
  new Promise((resolve, reject) => canvas.toBlob(b => (b ? resolve(b) : reject(new Error('toBlob'))), type, quality));

// A one-page A4 PDF whose only content is the certificate JPEG, scaled to the page.
async function jpegToPdf(jpegBlob, pxW, pxH) {
  const jpeg = new Uint8Array(await jpegBlob.arrayBuffer());
  const parts = [];
  const offsets = [];
  let length = 0;
  const push = chunk => {
    const bytes = typeof chunk === 'string' ? enc.encode(chunk) : chunk;
    parts.push(bytes);
    length += bytes.length;
  };
  const object = (n, write) => { offsets[n] = length; push(`${n} 0 obj\n`); write(); push('\nendobj\n'); };
  const { w, h } = PAGE_PT;
  const content = `q ${w} 0 0 ${h} 0 0 cm /Im0 Do Q`;

  push('%PDF-1.4\n');
  push(new Uint8Array([0x25, 0xe2, 0xe3, 0xcf, 0xd3, 0x0a])); // binary marker comment
  object(1, () => push('<< /Type /Catalog /Pages 2 0 R >>'));
  object(2, () => push('<< /Type /Pages /Kids [3 0 R] /Count 1 >>'));
  object(3, () => push(`<< /Type /Page /Parent 2 0 R /MediaBox [0 0 ${w} ${h}] /Resources << /XObject << /Im0 4 0 R >> >> /Contents 5 0 R >>`));
  object(4, () => {
    push(`<< /Type /XObject /Subtype /Image /Width ${pxW} /Height ${pxH} /ColorSpace /DeviceRGB /BitsPerComponent 8 /Filter /DCTDecode /Length ${jpeg.length} >>\nstream\n`);
    push(jpeg);
    push('\nendstream');
  });
  object(5, () => push(`<< /Length ${content.length} >>\nstream\n${content}\nendstream`));
  const xref = length;
  push('xref\n0 6\n0000000000 65535 f \n' + offsets.slice(1).map(o => `${String(o).padStart(10, '0')} 00000 n \n`).join(''));
  push(`trailer\n<< /Size 6 /Root 1 0 R >>\nstartxref\n${xref}\n%%EOF\n`);
  return new Blob(parts, { type: 'application/pdf' });
}

function setBusy(busy) {
  submit.disabled = busy;
  submit.innerHTML = busy
    ? '<span class="spinner" aria-hidden="true"></span><span class="label">جارٍ البحث…</span>'
    : '<span class="label">اعرض شهادتي</span>';
}

function showError(text) {
  msg.textContent = text;
  input.setAttribute('aria-invalid', text ? 'true' : 'false');
}

function releaseUrls() {
  while (objectUrls.length) URL.revokeObjectURL(objectUrls.pop());
}

const safeFileName = name => name.replace(/[\\/:*?"<>|]+/g, '').trim();

form.addEventListener('submit', async event => {
  event.preventDefault();
  const phone = normalizePhone(input.value);
  if (!phone) {
    showError('اكتب رقم الجوال بصيغة 05XXXXXXXX (10 أرقام).');
    input.focus();
    return;
  }
  showError('');
  setBusy(true);
  try {
    const data = await dataPromise;
    const name = await findName(phone, data);
    if (!name) {
      showError('لا توجد شهادة مسجّلة بهذا الرقم. تأكد أنه الرقم نفسه الذي سجّلت به في نموذج الحضور.');
      input.focus();
      return;
    }
    const [img] = await Promise.all([imagePromise, fontPromise]);
    const canvas = drawCertificate(img, name);
    const jpeg = await canvasToBlob(canvas, 'image/jpeg', 0.92);
    const pdf = await jpegToPdf(jpeg, canvas.width, canvas.height);

    releaseUrls();
    const jpegUrl = URL.createObjectURL(jpeg);
    const pdfUrl = URL.createObjectURL(pdf);
    objectUrls.push(jpegUrl, pdfUrl);
    const base = `شهادة حضور - ${safeFileName(name)}`;
    preview.src = jpegUrl;
    dlImg.href = jpegUrl;
    dlImg.download = `${base}.jpg`;
    dlPdf.href = pdfUrl;
    dlPdf.download = `${base}.pdf`;
    nameEl.textContent = name;

    form.hidden = true;
    result.hidden = false;
    result.scrollIntoView({ behavior: 'smooth', block: 'start' });
  } catch (err) {
    console.error(err);
    showError('تعذّر تحميل الشهادة. تحقق من اتصالك بالإنترنت ثم حاول مرة أخرى.');
  } finally {
    setBusy(false);
  }
});

input.addEventListener('input', () => { if (msg.textContent) showError(''); });

again.addEventListener('click', () => {
  result.hidden = true;
  form.hidden = false;
  input.value = '';
  releaseUrls();
  preview.removeAttribute('src');
  input.focus();
});
