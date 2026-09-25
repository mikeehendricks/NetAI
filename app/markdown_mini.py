"""Tiny, dependency-free Markdown renderer for the subset NetAI produces.
Supports: headings, tables, bold, italics, inline code, lists, hr, paragraphs.
All content is HTML-escaped first, so it is XSS-safe for user/LLM text."""
import re
from markupsafe import escape


def _inline(s: str) -> str:
    s = str(escape(s))
    s = re.sub(r"\*\*(.+?)\*\*", r"<strong>\1</strong>", s)
    s = re.sub(r"(?<!\*)\*([^*]+?)\*(?!\*)", r"<em>\1</em>", s)
    s = re.sub(r"`([^`]+?)`", r"<code>\1</code>", s)
    s = re.sub(r"\[([^\]]+?)\]\((https?://[^)\s]+)\)", r'<a href="\2" rel="noopener noreferrer">\1</a>', s)
    return s


def md_to_html(md: str) -> str:
    out, i = [], 0
    lines = md.splitlines()
    while i < len(lines):
        ln = lines[i]
        if not ln.strip():
            i += 1
            continue
        if re.match(r"^\s*```", ln):
            # fenced code block: collect verbatim, escape-first (XSS-safe)
            i += 1
            block = []
            while i < len(lines) and not re.match(r"^\s*```\s*$", lines[i]):
                block.append(lines[i])
                i += 1
            i += 1  # skip the closing fence (or run off the end for unterminated)
            body = str(escape("\n".join(block)))
            out.append('<pre class="code"><code>' + body + "</code></pre>")
            continue
        if ln.startswith("|") and i + 1 < len(lines) and re.match(r"^\|[\s:|-]+\|?\s*$", lines[i + 1]):
            # table
            header = [c.strip() for c in ln.strip("|").split("|")]
            i += 2
            rows = []
            while i < len(lines) and lines[i].startswith("|"):
                rows.append([c.strip() for c in lines[i].strip("|").split("|")])
                i += 1
            out.append('<table class="tbl mdtable"><thead><tr>')
            for h in header:
                out.append(f"<th>{_inline(h)}</th>")
            out.append("</tr></thead><tbody>")
            for r in rows:
                out.append("<tr>" + "".join(f"<td>{_inline(c)}</td>" for c in r) + "</tr>")
            out.append("</tbody></table>")
            continue
        m = re.match(r"^(#{1,4})\s+(.*)", ln)
        if m:
            lvl = min(len(m.group(1)), 4)
            out.append(f"<h{lvl+1}>{_inline(m.group(2))}</h{lvl+1}>")
            i += 1
            continue
        if re.match(r"^\s*---+\s*$", ln):
            out.append("<hr>")
            i += 1
            continue
        if re.match(r"^\s*([-*+])\s+", ln):
            out.append("<ul>")
            while i < len(lines) and re.match(r"^\s*([-*+])\s+", lines[i]):
                out.append(f"<li>{_inline(re.sub(r'^\s*([-*+])\s+', '', lines[i]))}</li>")
                i += 1
            out.append("</ul>")
            continue
        # paragraph (merge consecutive plain lines; fences end a paragraph)
        para = [ln]
        i += 1
        while i < len(lines) and lines[i].strip() and not re.match(r"^(\||#|\s*[-*+]\s|\s*---|\s*```)", lines[i]):
            para.append(lines[i])
            i += 1
        out.append(f"<p>{_inline(' '.join(para))}</p>")
    return "\n".join(out)
