"""Pure-stdlib colored .xlsx writer for the evidence summary — no openpyxl, so the
engine stays dependency-free. An .xlsx is a zip of OOXML parts; we hand-build a
minimal workbook with a styles table (one solid fill per verdict) and fill each
row's Verdict cell with its verdict colour. Opens cleanly in Excel / LibreOffice /
Google Sheets, with a frozen header row + autofilter.

    from evidence_xlsx import write_xlsx
    write_xlsx("summary.xlsx", records, verdict_of)   # records = list[dict]
"""
import io
import html
import zipfile

# column key in the record -> header label. "__verdict" is the computed effective
# verdict (coloured); everything else is read straight from the record.
COLS = [
    ("iteration", "It"), ("target_ip", "Target"), ("mode", "Posture"),
    ("category", "Category"), ("attack", "Module"), ("ports", "Ports"),
    ("__verdict", "Verdict"), ("verdict", "Detail"), ("mitre", "ATT&CK"),
    ("cwe", "CWE"), ("control_tested", "Control"), ("duration_s", "Dur(s)"),
    ("timestamp", "Time"),
]

# verdict -> (fill ARGB, font ARGB). Mirrors the dashboard / report.html palette.
VCOLOR = {
    "SUCCESS":       ("FFFF5D6C", "FFFFFFFF"),
    "DETECTED":      ("FFF6A43A", "FF231400"),
    "BLOCKED":       ("FF45D49A", "FF05240F"),
    "NO-SERVICE":    ("FF5796FF", "FFFFFFFF"),
    "INCONCLUSIVE":  ("FFB095FF", "FF160A33"),
    "AUTH-FAILED":   ("FFE2A336", "FF231400"),
    "NO-RESULT":     ("FF64778A", "FFFFFFFF"),
    "SKIPPED":       ("FF64778A", "FFFFFFFF"),
    "PREREQ-MISSING":("FF64778A", "FFFFFFFF"),
}
_HEADER_FILL = "FF0F151B"
_HEADER_FONT = "FFE7EEF5"


def _colref(i):           # 0 -> A, 25 -> Z, 26 -> AA
    s = ""; i += 1
    while i:
        i, r = divmod(i - 1, 26)
        s = chr(65 + r) + s
    return s


def _cell(ref, text, style):
    return (f'<c r="{ref}" s="{style}" t="inlineStr"><is>'
            f'<t xml:space="preserve">{html.escape(str(text))}</t></is></c>')


def _default_verdict_of(r):
    return (r.get("appliance_result") if r.get("appliance_ip") is not None
            else r.get("baseline_result")) or "?"


def build_xlsx(records, verdict_of=None):
    """Return the bytes of a coloured .xlsx summarising `records`."""
    verdict_of = verdict_of or _default_verdict_of

    # ---- styles: fonts, fills, cellXfs (index 0 default, 1 header, then verdicts)
    fonts = ['<font><sz val="10"/><name val="Calibri"/></font>',
             f'<font><b/><sz val="10"/><color rgb="{_HEADER_FONT}"/><name val="Calibri"/></font>']
    fills = ['<fill><patternFill patternType="none"/></fill>',
             '<fill><patternFill patternType="gray125"/></fill>',
             f'<fill><patternFill patternType="solid"><fgColor rgb="{_HEADER_FILL}"/>'
             '<bgColor indexed="64"/></patternFill></fill>']
    xfs = ['<xf fontId="0" fillId="0" borderId="0" xfId="0"/>',
           '<xf fontId="1" fillId="2" borderId="0" xfId="0" applyFont="1" applyFill="1"/>']
    HEADER_XF = 1
    vxf = {}
    for v, (fill, font) in VCOLOR.items():
        fonts.append(f'<font><b/><sz val="10"/><color rgb="{font}"/><name val="Calibri"/></font>')
        fills.append(f'<fill><patternFill patternType="solid"><fgColor rgb="{fill}"/>'
                     '<bgColor indexed="64"/></patternFill></fill>')
        xfs.append(f'<xf fontId="{len(fonts)-1}" fillId="{len(fills)-1}" borderId="0" '
                   'xfId="0" applyFont="1" applyFill="1"/>')
        vxf[v] = len(xfs) - 1

    styles = ('<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
              '<styleSheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">'
              f'<fonts count="{len(fonts)}">{"".join(fonts)}</fonts>'
              f'<fills count="{len(fills)}">{"".join(fills)}</fills>'
              '<borders count="1"><border/></borders>'
              '<cellStyleXfs count="1"><xf numFmtId="0" fontId="0" fillId="0" borderId="0"/></cellStyleXfs>'
              f'<cellXfs count="{len(xfs)}">{"".join(xfs)}</cellXfs>'
              '<cellStyles count="1"><cellStyle name="Normal" xfId="0" builtinId="0"/></cellStyles>'
              '</styleSheet>')

    # ---- sheet rows
    rows = ["<row r=\"1\">" + "".join(
        _cell(f"{_colref(j)}1", lbl, HEADER_XF) for j, (_k, lbl) in enumerate(COLS)) + "</row>"]
    rn = 1
    for r in records:
        rn += 1
        v = verdict_of(r)
        cells = []
        for j, (k, _lbl) in enumerate(COLS):
            if k == "__verdict":
                val, st = v, vxf.get(v, 0)
            else:
                val = r.get(k, "")
                if isinstance(val, list):
                    val = ", ".join(str(x) for x in val)
                st = 0
            cells.append(_cell(f"{_colref(j)}{rn}", val, st))
        rows.append(f'<row r="{rn}">' + "".join(cells) + "</row>")

    last = _colref(len(COLS) - 1)
    sheet = ('<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
             '<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">'
             '<sheetViews><sheetView workbookViewId="0">'
             '<pane ySplit="1" topLeftCell="A2" activePane="bottomLeft" state="frozen"/>'
             '</sheetView></sheetViews><sheetFormatPr defaultRowHeight="15"/>'
             '<cols><col min="2" max="2" width="17"/><col min="5" max="5" width="34"/>'
             '<col min="6" max="6" width="18"/><col min="7" max="7" width="14"/>'
             '<col min="8" max="8" width="60"/><col min="11" max="11" width="30"/></cols>'
             f'<sheetData>{"".join(rows)}</sheetData>'
             f'<autoFilter ref="A1:{last}{rn}"/></worksheet>')

    ct = ('<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
          '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
          '<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>'
          '<Default Extension="xml" ContentType="application/xml"/>'
          '<Override PartName="/xl/workbook.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/>'
          '<Override PartName="/xl/worksheets/sheet1.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/>'
          '<Override PartName="/xl/styles.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.styles+xml"/>'
          '</Types>')
    rels = ('<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
            '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
            '<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="xl/workbook.xml"/>'
            '</Relationships>')
    wb = ('<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
          '<workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" '
          'xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships">'
          '<sheets><sheet name="Results" sheetId="1" r:id="rId1"/></sheets></workbook>')
    wbrels = ('<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
              '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
              '<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" Target="worksheets/sheet1.xml"/>'
              '<Relationship Id="rId2" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/styles" Target="styles.xml"/>'
              '</Relationships>')

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("[Content_Types].xml", ct)
        z.writestr("_rels/.rels", rels)
        z.writestr("xl/workbook.xml", wb)
        z.writestr("xl/_rels/workbook.xml.rels", wbrels)
        z.writestr("xl/styles.xml", styles)
        z.writestr("xl/worksheets/sheet1.xml", sheet)
    return buf.getvalue()


def write_xlsx(path, records, verdict_of=None):
    with open(path, "wb") as f:
        f.write(build_xlsx(records, verdict_of))
    return path
