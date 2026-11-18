--[[
Pandoc Lua filter for the Word edition of the Keyring Solution Design Document.

The Markdown sources are shared with the PDF. This filter only shapes the Word output:
- a cover page, the document control block (from metadata `control`) and a real Word TOC field, in that order;
- short, stable heading bookmarks (sec1, sec4_2, ...) so the TOC links and PAGEREF fields work;
- `::: note` and `::: unconfirmed` divs become the "Note" and "Not Confirmed" paragraph styles;
- `::: wide` and `::: compact` divs are unwrapped (they only matter to the PDF);
- diagrams are embedded at full text width;
- table column widths follow the content, so short code columns stay narrow.
]]

local stringify = pandoc.utils.stringify

local function raw(xml) return pandoc.RawBlock("openxml", xml) end

local function esc(s)
  return (s:gsub("&", "&amp;"):gsub("<", "&lt;"):gsub(">", "&gt;"))
end

local PAGE_BREAK = raw('<w:p><w:r><w:br w:type="page"/></w:r></w:p>')

local function Div(div)
  local c = div.classes
  if c:includes("note") then
    div.attributes["custom-style"] = "Note"
    div.classes = {}
    return div
  elseif c:includes("unconfirmed") then
    div.attributes["custom-style"] = "Not Confirmed"
    div.classes = {}
    return div
  elseif c:includes("wide") or c:includes("compact") or c:includes("landscape") then
    return div.content
  end
end

local function Figure(fig)
  return pandoc.walk_block(fig, {
    Image = function(img)
      if not img.attributes.width then img.attributes.width = "100%" end
      return img
    end,
  })
end

-- Column widths from content: long text gets more room, short codes stay compact.
local function Table(tbl)
  local n = #tbl.colspecs
  if n == 0 then return nil end
  local maxlen, total = {}, {}
  local rows = 0
  local function measure(row)
    for i, cell in ipairs(row.cells) do
      if i <= n then
        local len = utf8.len(stringify(cell.contents)) or 0
        maxlen[i] = math.max(maxlen[i] or 0, len)
        total[i] = (total[i] or 0) + len
      end
    end
  end
  for _, row in ipairs(tbl.head.rows) do measure(row) end
  for _, body in ipairs(tbl.bodies) do
    for _, row in ipairs(body.body) do
      measure(row)
      rows = rows + 1
    end
  end
  local weights, sum = {}, 0
  for i = 1, n do
    local avg = (total[i] or 0) / math.max(rows + 1, 1)
    local w = math.max(4, 0.6 * math.min(maxlen[i] or 0, 60) + 0.4 * avg)
    weights[i] = math.sqrt(w)
    sum = sum + weights[i]
  end
  for i = 1, n do
    tbl.colspecs[i] = { tbl.colspecs[i][1], math.max(weights[i] / sum, 0.07) }
  end
  local s2 = 0
  for i = 1, n do s2 = s2 + tbl.colspecs[i][2] end
  for i = 1, n do tbl.colspecs[i] = { tbl.colspecs[i][1], tbl.colspecs[i][2] / s2 } end
  return tbl
end

local function styled(style, text)
  return pandoc.Div({ pandoc.Para(pandoc.Inlines(text)) }, { ["custom-style"] = style })
end

local function cover(meta)
  local blocks = {
    styled("Cover Kicker", "Solution Design Document"),
    styled("Title", "Keyring"),
    styled("Subtitle", "A plain-English web front end for Azure Key Vault"),
    styled("Cover Note", "Acts as the signed-in person. Stores nothing."),
  }
  local md = "| Item | Value |\n|---|---|\n"
    .. "| Version | " .. stringify(meta.version) .. " |\n"
    .. "| Date | " .. stringify(meta.date) .. " |\n"
    .. "| Status | " .. stringify(meta.status) .. " |\n"
    .. "| Repository | `github.com/jusso-dev/keyring` |\n"
  for _, b in ipairs(pandoc.read(md, "markdown").blocks) do table.insert(blocks, b) end
  table.insert(blocks, styled("Not Confirmed", "Draft for review. Not reviewed, approved or endorsed by anyone."))
  table.insert(blocks, PAGE_BREAK)
  return blocks
end

local function run(text) return '<w:r><w:t xml:space="preserve">' .. esc(text) .. "</w:t></w:r>" end

local function toc_entry(level, anchor, label, first, last)
  local xml = '<w:p><w:pPr><w:pStyle w:val="TOC' .. level .. '"/></w:pPr>'
  if first then
    xml = xml .. '<w:r><w:fldChar w:fldCharType="begin" w:dirty="true"/></w:r>'
      .. '<w:r><w:instrText xml:space="preserve"> TOC \\o "1-2" \\h \\z \\u </w:instrText></w:r>'
      .. '<w:r><w:fldChar w:fldCharType="separate"/></w:r>'
  end
  xml = xml .. '<w:hyperlink w:anchor="' .. anchor .. '" w:history="1">' .. run(label) .. "<w:r><w:tab/></w:r>"
    .. '<w:r><w:fldChar w:fldCharType="begin"/></w:r>'
    .. '<w:r><w:instrText xml:space="preserve"> PAGEREF ' .. anchor .. ' \\h </w:instrText></w:r>'
    .. '<w:r><w:fldChar w:fldCharType="separate"/></w:r>' .. run("")
    .. '<w:r><w:fldChar w:fldCharType="end"/></w:r></w:hyperlink>'
  if last then xml = xml .. '<w:r><w:fldChar w:fldCharType="end"/></w:r>' end
  return xml .. "</w:p>"
end

function Pandoc(doc)
  local n1, n2, n3 = 0, 0, 0
  local entries = {}
  doc.blocks = doc.blocks:walk({
    Header = function(h)
      if h.classes:includes("unnumbered") then return nil end
      if h.level == 1 then
        n1, n2, n3 = n1 + 1, 0, 0
        h.identifier = "sec" .. n1
        table.insert(entries, { 1, h.identifier, n1 .. "  " .. stringify(h.content) })
      elseif h.level == 2 then
        n2, n3 = n2 + 1, 0
        h.identifier = "sec" .. n1 .. "_" .. n2
        table.insert(entries, { 2, h.identifier, n1 .. "." .. n2 .. "  " .. stringify(h.content) })
      elseif h.level == 3 then
        n3 = n3 + 1
        h.identifier = "sec" .. n1 .. "_" .. n2 .. "_" .. n3
      end
      return h
    end,
  })
  doc.blocks = doc.blocks:walk({ Div = Div, Figure = Figure, Table = Table })

  local front = cover(doc.meta)

  if doc.meta.control then
    local control = pandoc.Blocks(doc.meta.control):walk({
      Header = function(h)
        return pandoc.Div({ pandoc.Para(h.content) }, { ["custom-style"] = "Control Heading" })
      end,
      Table = Table,
    })
    for _, b in ipairs(control) do table.insert(front, b) end
  end

  table.insert(front, PAGE_BREAK)
  local toc = '<w:sdt><w:sdtPr><w:docPartObj><w:docPartGallery w:val="Table of Contents"/><w:docPartUnique/>'
    .. '</w:docPartObj></w:sdtPr><w:sdtContent>'
    .. '<w:p><w:pPr><w:pStyle w:val="TOCHeading"/></w:pPr>' .. run("Contents") .. "</w:p>"
  for i, e in ipairs(entries) do
    toc = toc .. toc_entry(e[1], e[2], e[3], i == 1, i == #entries)
  end
  toc = toc .. "</w:sdtContent></w:sdt>"
  table.insert(front, raw(toc))

  local blocks = pandoc.Blocks(front)
  blocks:extend(doc.blocks)
  doc.blocks = blocks
  for _, k in ipairs({ "title", "running-title", "subtitle", "author", "date", "status", "version", "control" }) do
    doc.meta[k] = nil
  end
  return doc
end
