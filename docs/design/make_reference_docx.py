#!/usr/bin/env python3
"""Builds docs/design/reference.docx: the Word styles pandoc uses for Keyring-Design-Document.docx.

Python 3 standard library only, and deterministic (fixed zip timestamps and order), so the same inputs give
the same file. It starts from pandoc's own default reference.docx (pandoc must be on PATH) and replaces:

- styles.xml: Keyring's look from design.md. Ink #1c222a text, slate teal #186575 accents, the chrome
  colour #1d252d for table header rows, real Word heading styles (Heading 1 to 4 with outline levels) so the
  navigation pane and the TOC field work, TOC 1 to 3, captions, callouts and a ledger-style table.
  design.md uses the operating system's own fonts and loads no font files, so no font is embedded: the body
  asks for Segoe UI (Windows) with Helvetica Neue and Arial as fallbacks, code for Consolas then Menlo.
- settings.xml: update fields on open (so the TOC and figure numbers fill in), en-AU proofing.
- header1.xml, footer1.xml and the final section properties: title, version, status and date, "Page X of Y",
  A4 portrait.

Usage: python3 docs/design/make_reference_docx.py
"""
import io
import os
import re
import subprocess
import zipfile
from xml.sax.saxutils import escape as xml_escape

HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(HERE, "reference.docx")


def meta(key):
    """Read one plain `key: "value"` line from metadata.yaml, so the header matches the PDF."""
    with open(os.path.join(HERE, "metadata.yaml"), encoding="utf-8") as f:
        for line in f:
            m = re.match(rf'^{re.escape(key)}:\s*"?([^"\n]*)"?\s*$', line)
            if m:
                return m.group(1)
    raise SystemExit(f"metadata.yaml has no {key}")


DOC_TITLE = meta("running-title")
DOC_VERSION = meta("version")
DOC_DATE = meta("date")
DOC_STATUS = meta("status")

INK, INK2, ACCENT, ACCENT_TINT, PAPER, PAPER2, RULE, CHROME, CHROME_INK = (
    "1C222A", "515963", "186575", "E3F4F8", "F5F7FA", "EBEFF2", "DADEE3", "1D252D", "F3F5F8")
WARN, WARN_TINT = "804D0C", "FDF2DD"
BODY, MONO = "Segoe UI", "Consolas"
FIXED_TIME = (2026, 11, 18, 0, 0, 0)

W = 'xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"'
R = 'xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"'


def rfonts(name):
    return f'<w:rFonts w:ascii="{name}" w:hAnsi="{name}" w:cs="{name}" w:eastAsia="{name}"/>'


def para_style(sid, name, ppr="", rpr="", based="Normal", nxt=None, ui=None, q=True):
    nx = f'<w:next w:val="{nxt}"/>' if nxt else ""
    pri = f'<w:uiPriority w:val="{ui}"/>' if ui is not None else ""
    return (f'<w:style w:type="paragraph" w:customStyle="0" w:styleId="{sid}"><w:name w:val="{name}"/>'
            f'<w:basedOn w:val="{based}"/>{nx}{pri}{"<w:qFormat/>" if q else ""}'
            f'<w:pPr>{ppr}</w:pPr><w:rPr>{rpr}</w:rPr></w:style>')


def char_style(sid, name, rpr, based="DefaultParagraphFont"):
    return (f'<w:style w:type="character" w:styleId="{sid}"><w:name w:val="{name}"/>'
            f'<w:basedOn w:val="{based}"/><w:rPr>{rpr}</w:rPr></w:style>')


def border(side, sz=4, colour=RULE, space=0):
    return f'<w:{side} w:val="single" w:sz="{sz}" w:space="{space}" w:color="{colour}"/>'


def callout(sid, name, edge, fill):
    return para_style(sid, name,
                      f'<w:pBdr>{border("left", 24, edge, 8)}</w:pBdr><w:shd w:val="clear" w:color="auto" w:fill="{fill}"/>'
                      '<w:spacing w:before="80" w:after="160"/><w:ind w:left="170" w:right="113"/>', based="BodyText")


def styles_xml():
    body_rpr = rfonts(BODY) + f'<w:color w:val="{INK}"/><w:sz w:val="19"/><w:szCs w:val="19"/><w:lang w:val="en-AU"/>'
    s = [f'<?xml version="1.0" encoding="UTF-8" standalone="yes"?><w:styles {W}>',
         f'<w:docDefaults><w:rPrDefault><w:rPr>{body_rpr}</w:rPr></w:rPrDefault>'
         '<w:pPrDefault><w:pPr><w:spacing w:after="120" w:line="264" w:lineRule="auto"/></w:pPr></w:pPrDefault></w:docDefaults>',
         '<w:style w:type="paragraph" w:default="1" w:styleId="Normal"><w:name w:val="Normal"/><w:qFormat/>'
         '<w:pPr><w:spacing w:after="120" w:line="264" w:lineRule="auto"/></w:pPr><w:rPr/></w:style>',
         '<w:style w:type="character" w:default="1" w:styleId="DefaultParagraphFont"><w:name w:val="Default Paragraph Font"/>'
         '<w:uiPriority w:val="1"/><w:semiHidden/><w:unhideWhenUsed/></w:style>',
         '<w:style w:type="table" w:default="1" w:styleId="TableNormal"><w:name w:val="Normal Table"/><w:uiPriority w:val="99"/>'
         '<w:semiHidden/><w:unhideWhenUsed/><w:tblPr><w:tblInd w:w="0" w:type="dxa"/><w:tblCellMar><w:top w:w="0" w:type="dxa"/>'
         '<w:left w:w="108" w:type="dxa"/><w:bottom w:w="0" w:type="dxa"/><w:right w:w="108" w:type="dxa"/></w:tblCellMar></w:tblPr></w:style>',
         '<w:style w:type="numbering" w:default="1" w:styleId="NoList"><w:name w:val="No List"/><w:uiPriority w:val="99"/>'
         '<w:semiHidden/><w:unhideWhenUsed/></w:style>']
    s.append(para_style("BodyText", "Body Text", '<w:spacing w:before="0" w:after="120"/>', nxt="BodyText"))
    s.append(para_style("FirstParagraph", "First Paragraph", based="BodyText", nxt="BodyText"))
    s.append(para_style("Compact", "Compact", '<w:spacing w:before="20" w:after="20" w:line="240" w:lineRule="auto"/>',
                        '<w:sz w:val="16"/><w:szCs w:val="16"/>', based="BodyText"))
    sizes = {1: 36, 2: 25, 3: 21, 4: 19}
    for lvl in (1, 2, 3, 4):
        ppr = (f'<w:keepNext/><w:keepLines/><w:spacing w:before="{[0, 0, 280, 220, 180][lvl]}" w:after="{[0, 160, 100, 80, 60][lvl]}"/>'
               f'<w:outlineLvl w:val="{lvl - 1}"/>')
        if lvl == 1:
            ppr = ('<w:keepNext/><w:keepLines/><w:pageBreakBefore/>'
                   f'<w:pBdr>{border("bottom", 12, ACCENT, 6)}</w:pBdr><w:spacing w:before="0" w:after="240"/><w:outlineLvl w:val="0"/>')
        rpr = f'<w:b/><w:bCs/><w:color w:val="{INK if lvl == 1 else ACCENT}"/><w:sz w:val="{sizes[lvl]}"/><w:szCs w:val="{sizes[lvl]}"/>'
        s.append(para_style(f"Heading{lvl}", f"heading {lvl}", ppr, rpr, nxt="BodyText", ui=9))
    for lvl in range(5, 10):
        s.append(para_style(f"Heading{lvl}", f"heading {lvl}", f'<w:keepNext/><w:outlineLvl w:val="{lvl - 1}"/>',
                            "<w:b/>", nxt="BodyText", ui=9))
    s.append(char_style("SectionNumber", "Section Number", f'<w:color w:val="{ACCENT}"/>'))
    s.append(para_style("Title", "Title", '<w:spacing w:before="0" w:after="120"/>',
                        f'<w:b/><w:color w:val="{INK}"/><w:sz w:val="92"/><w:szCs w:val="92"/>', nxt="BodyText", ui=10))
    s.append(para_style("Subtitle", "Subtitle", '<w:spacing w:before="0" w:after="120"/>',
                        f'<w:b/><w:color w:val="{INK}"/><w:sz w:val="32"/><w:szCs w:val="32"/>', nxt="BodyText", ui=11))
    s.append(para_style("CoverKicker", "Cover Kicker", '<w:spacing w:before="3000" w:after="120"/>',
                        f'<w:b/><w:caps/><w:color w:val="{ACCENT}"/><w:spacing w:val="30"/><w:sz w:val="21"/>'))
    s.append(para_style("CoverNote", "Cover Note", '<w:spacing w:before="0" w:after="600"/>',
                        f'<w:color w:val="{INK2}"/><w:sz w:val="24"/><w:szCs w:val="24"/>'))
    s.append(para_style("ControlHeading", "Control Heading", '<w:keepNext/><w:spacing w:before="240" w:after="100"/>',
                        f'<w:b/><w:color w:val="{ACCENT}"/><w:sz w:val="25"/><w:szCs w:val="25"/>', nxt="BodyText"))
    for sid, name in (("Author", "Author"), ("Date", "Date"), ("AbstractTitle", "Abstract Title"), ("Abstract", "Abstract"),
                      ("Bibliography", "Bibliography"), ("BlockText", "Block Text"), ("FootnoteText", "Footnote Text"),
                      ("FootnoteBlockText", "Footnote Block Text"), ("DefinitionTerm", "Definition Term"), ("Definition", "Definition")):
        s.append(para_style(sid, name, based="BodyText", q=False))
    cap_rpr = f'<w:color w:val="{INK2}"/><w:sz w:val="16"/><w:szCs w:val="16"/>'
    s.append(para_style("Caption", "caption", '<w:spacing w:before="60" w:after="240"/>', cap_rpr, ui=35))
    s.append(para_style("TableCaption", "Table Caption", '<w:keepNext/><w:spacing w:before="120" w:after="80"/>', cap_rpr + "<w:b/>",
                        based="Caption"))
    s.append(para_style("ImageCaption", "Image Caption", '<w:spacing w:before="60" w:after="240"/>', cap_rpr, based="Caption"))
    s.append(para_style("Figure", "Figure", '<w:jc w:val="center"/><w:spacing w:before="120" w:after="0"/>', based="Normal", q=False))
    s.append(para_style("CaptionedFigure", "Captioned Figure", '<w:keepNext/><w:jc w:val="center"/>', based="Figure", q=False))
    s.append(callout("Note", "Note", INK2, PAPER))
    s.append(callout("NotConfirmed", "Not Confirmed", WARN, WARN_TINT))
    s.append(para_style("SourceCode", "Source Code",
                        f'<w:pBdr>{border("left", 18, ACCENT, 6)}</w:pBdr><w:shd w:val="clear" w:color="auto" w:fill="{PAPER}"/>'
                        '<w:wordWrap w:val="off"/><w:spacing w:before="0" w:after="160" w:line="240" w:lineRule="auto"/><w:ind w:left="113"/>',
                        rfonts(MONO) + '<w:sz w:val="15"/><w:szCs w:val="15"/>', q=False))
    s.append(char_style("VerbatimChar", "Verbatim Char", rfonts(MONO) + f'<w:sz w:val="16"/><w:shd w:val="clear" w:color="auto" w:fill="{PAPER2}"/>'))
    s.append(char_style("Hyperlink", "Hyperlink", f'<w:color w:val="{ACCENT}"/>'))
    s.append(char_style("FootnoteReference", "Footnote Reference", '<w:vertAlign w:val="superscript"/>'))
    s.append(char_style("BodyTextChar", "Body Text Char", ""))
    s.append(para_style("TOCHeading", "TOC Heading", f'<w:pBdr>{border("bottom", 12, ACCENT, 6)}</w:pBdr><w:spacing w:before="0" w:after="240"/>',
                        f'<w:b/><w:color w:val="{INK}"/><w:sz w:val="36"/>', based="Normal", nxt="BodyText", ui=39))
    tabs = '<w:tabs><w:tab w:val="right" w:leader="dot" w:pos="9638"/></w:tabs>'
    s.append(para_style("TOC1", "toc 1", f'{tabs}<w:spacing w:before="120" w:after="20"/>', '<w:b/><w:sz w:val="20"/>', nxt="BodyText", ui=39, q=False))
    s.append(para_style("TOC2", "toc 2", f'{tabs}<w:spacing w:before="0" w:after="0"/><w:ind w:left="340"/>', '<w:sz w:val="18"/>', nxt="BodyText", ui=39, q=False))
    s.append(para_style("TOC3", "toc 3", f'{tabs}<w:spacing w:before="0" w:after="0"/><w:ind w:left="680"/>', '<w:sz w:val="17"/>', nxt="BodyText", ui=39, q=False))
    s.append(para_style("Header", "header", '<w:tabs><w:tab w:val="center" w:pos="4819"/><w:tab w:val="right" w:pos="9638"/></w:tabs><w:spacing w:after="0"/>',
                        f'<w:color w:val="{INK2}"/><w:sz w:val="15"/>', q=False))
    s.append(para_style("Footer", "footer", '<w:tabs><w:tab w:val="center" w:pos="4819"/><w:tab w:val="right" w:pos="9638"/></w:tabs><w:spacing w:after="0"/>',
                        f'<w:color w:val="{INK2}"/><w:sz w:val="15"/>', q=False))
    cell_mar = ('<w:tblCellMar><w:top w:w="57" w:type="dxa"/><w:left w:w="85" w:type="dxa"/>'
                '<w:bottom w:w="57" w:type="dxa"/><w:right w:w="85" w:type="dxa"/></w:tblCellMar>')
    s.append('<w:style w:type="table" w:styleId="Table"><w:name w:val="Table"/><w:basedOn w:val="TableNormal"/><w:uiPriority w:val="59"/>'
             '<w:pPr><w:spacing w:before="20" w:after="20" w:line="240" w:lineRule="auto"/></w:pPr><w:rPr><w:sz w:val="16"/><w:szCs w:val="16"/></w:rPr>'
             f'<w:tblPr><w:tblStyleRowBandSize w:val="1"/><w:tblBorders>{border("top", 4, RULE)}{border("bottom", 4, RULE)}'
             f'{border("insideH", 4, RULE)}</w:tblBorders>{cell_mar}</w:tblPr>'
             f'<w:tblStylePr w:type="firstRow"><w:pPr><w:keepNext/></w:pPr><w:rPr><w:b/><w:color w:val="{CHROME_INK}"/></w:rPr>'
             f'<w:tblPr/><w:trPr><w:tblHeader/></w:trPr><w:tcPr><w:shd w:val="clear" w:color="auto" w:fill="{CHROME}"/><w:vAlign w:val="bottom"/></w:tcPr></w:tblStylePr>'
             f'<w:tblStylePr w:type="band2Horz"><w:tblPr/><w:tcPr><w:shd w:val="clear" w:color="auto" w:fill="{PAPER}"/></w:tcPr></w:tblStylePr>'
             '</w:style>')
    s.append('</w:styles>')
    return "".join(s)


def run(text, rpr=""):
    return f'<w:r><w:rPr>{rpr}</w:rPr><w:t xml:space="preserve">{xml_escape(text)}</w:t></w:r>'


def field(instr, placeholder):
    return ('<w:r><w:fldChar w:fldCharType="begin"/></w:r>'
            f'<w:r><w:instrText xml:space="preserve"> {instr} </w:instrText></w:r>'
            f'<w:r><w:fldChar w:fldCharType="separate"/></w:r>{run(placeholder)}'
            '<w:r><w:fldChar w:fldCharType="end"/></w:r>')


def header_xml():
    return (f'<?xml version="1.0" encoding="UTF-8" standalone="yes"?><w:hdr {W} {R}>'
            f'<w:p><w:pPr><w:pStyle w:val="Header"/><w:pBdr>{border("bottom", 4, RULE, 4)}</w:pBdr><w:spacing w:after="120"/></w:pPr>'
            f'{run(DOC_TITLE)}<w:r><w:tab/></w:r><w:r><w:tab/></w:r>{run("Version " + DOC_VERSION + " · " + DOC_STATUS)}</w:p></w:hdr>')


def footer_xml():
    return (f'<?xml version="1.0" encoding="UTF-8" standalone="yes"?><w:ftr {W} {R}>'
            f'<w:p><w:pPr><w:pStyle w:val="Footer"/><w:pBdr>{border("top", 4, RULE, 4)}</w:pBdr></w:pPr>'
            f'{run(DOC_DATE)}<w:r><w:tab/></w:r><w:r><w:tab/></w:r>{run("Page ")}{field("PAGE", "1")}{run(" of ")}{field("NUMPAGES", "1")}</w:p>'
            '</w:ftr>')


SECT = ('<w:sectPr><w:headerReference w:type="default" r:id="rIdKeyringHeader"/><w:footerReference w:type="default" r:id="rIdKeyringFooter"/>'
        '<w:footnotePr><w:numRestart w:val="eachSect"/></w:footnotePr>'
        '<w:pgSz w:w="11906" w:h="16838"/><w:pgMar w:top="1304" w:right="964" w:bottom="1191" w:left="964" w:header="567" w:footer="510" w:gutter="0"/>'
        '<w:cols w:space="708"/></w:sectPr>')


def main():
    default = subprocess.run(["pandoc", "--print-default-data-file", "reference.docx"], capture_output=True, check=True).stdout
    zin = zipfile.ZipFile(io.BytesIO(default))
    files = {i.filename: zin.read(i.filename) for i in zin.infolist()}

    files["word/styles.xml"] = styles_xml().encode()
    files["word/header1.xml"] = header_xml().encode()
    files["word/footer1.xml"] = footer_xml().encode()

    st = files["word/settings.xml"].decode()
    st = st.replace('<w:defaultTabStop', '<w:updateFields w:val="true"/><w:defaultTabStop', 1)
    st = st.replace('<w:themeFontLang w:val="en-US" />', '<w:themeFontLang w:val="en-AU" />')
    files["word/settings.xml"] = st.encode()

    doc = files["word/document.xml"].decode()
    doc = re.sub(r"<w:sectPr>.*?</w:sectPr>", SECT, doc, flags=re.S)
    files["word/document.xml"] = doc.encode()

    rels = files["word/_rels/document.xml.rels"].decode().replace(
        "</Relationships>",
        '<Relationship Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/header" Id="rIdKeyringHeader" Target="header1.xml" />'
        '<Relationship Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/footer" Id="rIdKeyringFooter" Target="footer1.xml" />'
        "</Relationships>")
    files["word/_rels/document.xml.rels"] = rels.encode()

    ct = files["[Content_Types].xml"].decode().replace(
        "<Default Extension=\"xml\"",
        '<Override PartName="/word/header1.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.header+xml" />'
        '<Override PartName="/word/footer1.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.footer+xml" />'
        "<Default Extension=\"xml\"", 1)
    files["[Content_Types].xml"] = ct.encode()

    with zipfile.ZipFile(OUT, "w", zipfile.ZIP_DEFLATED) as z:
        for name in sorted(files, key=lambda n: (n != "[Content_Types].xml", n)):
            info = zipfile.ZipInfo(name, FIXED_TIME)
            info.compress_type = zipfile.ZIP_DEFLATED
            z.writestr(info, files[name])
    print(f"Wrote {OUT}")


if __name__ == "__main__":
    main()
