"""Find where the user should sign, from identity text (name, role, ...) found in the PDF.

For every place where an identity appears:
  * nearest signature field within reach is EMPTY  -> sign into that field
  * nearest signature field within reach is SIGNED -> already done, skip
  * an empty box is DRAWN in the page next to it    -> sign exactly into that box (no extra frame)
  * otherwise                                       -> propose a new box next to the text, fitted
                                                       between the surrounding text / table lines
Names are primary, decided PER PAGE: on a page where one of your names appears, roles (and other
identity entries) are only merged into a name location when they sit right next to it (so a role
shared with other signers, e.g. "Member" under someone else's name, is ignored). On a page without
your name, the role itself marks the place (e.g. "THE REQUESTING PERSON IN CHARGE:" on a form).

Ranking (so a name in a member list on page 1 is not mistaken for a signature place):
  1. locations tied to a signature field (empty or signed);
  2. new-box locations with a signature cue nearby (dotted/underscore/drawn line, "Signature");
  3. bare mentions (no field, no cue).
Bare mentions are only used when the document has nothing better; otherwise they are reported
as "mention". Tier-2 locations are never dropped, so the remaining steps of a field-less
multi-step form stay available after the first step has been signed.
Matching ignores case, accents and punctuation; multi-word entries must be adjacent words.
Names match in any word order ("Maria Papadopoulou" = "PAPADOPOULOU MARIA", the usual order
in Greek administrative forms) and with all but one word abbreviated to its initial
("M. Papadopoulou", "Papadopoulou M."); roles must keep their word order.
"""

from __future__ import annotations

import itertools
import math
import re
import unicodedata
from dataclasses import dataclass, field

import pymupdf

from .config import Identities
from .signing import Placement, list_signature_fields

MERGE_GAP_PT = 30        # identity hits closer than this form one location
CUE_DIST_PT = 45         # signature cue must be this close to the identity text
CUE_WORDS = {"signature", "signatures", "signed", "sign", "υπογραφη", "υπογραφεσ", "υπογραφες"}
_LINE_CHARS = set("._…-_·")


def _norm(s: str) -> str:
    s = unicodedata.normalize("NFKD", s)
    s = "".join(c for c in s if not unicodedata.combining(c)).casefold()
    return "".join(c for c in s if c.isalnum())


def _tokens(term: str) -> list[str]:
    return [t for t in (_norm(x) for x in re.split(r"[\s.,;:/()\-]+", term)) if t]


def _aligned(text: pymupdf.Rect, box: pymupdf.Rect) -> bool:
    """A field/box belongs to a text only if it is beside it (vertical ranges overlap) or
    above/below it (horizontal ranges overlap) - never diagonal, which is typically the
    slot of the NEXT label (e.g. the director's box under the requester's)."""
    v = min(text.y1, box.y1) - max(text.y0, box.y0)
    h = min(text.x1, box.x1) - max(text.x0, box.x0)
    return v > 0 or h > 0


def _gap(a: pymupdf.Rect, b: pymupdf.Rect, xw: float = 1.0) -> float:
    dx = max(0.0, a.x0 - b.x1, b.x0 - a.x1)
    dy = max(0.0, a.y0 - b.y1, b.y0 - a.y1)
    return math.hypot(dx * xw, dy)


@dataclass
class _Word:
    norm: str
    rect: pymupdf.Rect
    raw: str = ""


@dataclass
class Location:
    page: int                          # 0-based
    text_rect: pymupdf.Rect            # identity text (unrotated page coordinates)
    terms: list[str]
    status: str                        # "field" | "new" | "signed" | "mention"
    field_name: str | None = None
    box: pymupdf.Rect | None = None    # field rect or proposed new box (unrotated page coords)
    box_pdf: tuple | None = None       # new box in PDF user space (x1, y1, x2, y2)
    order: int = 0
    cue: bool = False                  # signature line / label next to a "new" location
    space: bool = False                # cue is free signing space above a stand-alone name
    merged: int = 1                    # number of side-by-side places sharing this signature
    drawn: bool = False                # "new" box is an empty rectangle drawn in the page
    anchor: str | None = None          # PDF edge of a proposed box that faces the text

    @property
    def unsigned(self) -> bool:
        return self.status in ("field", "new")

    def placement(self) -> Placement:
        if self.status == "field":
            return Placement(field_name=self.field_name, page=self.page, box=None)
        return Placement(field_name=None, page=self.page, box=self.box_pdf, frame=not self.drawn,
                         fit=None if self.drawn else self.anchor)

    def describe(self) -> str:
        what = {"field": f"empty field '{self.field_name}'",
                "signed": f"already signed ('{self.field_name}')",
                "new": ("empty box drawn next to the text" if self.drawn else
                        "new box next to the text" + (" (signature space above the name)" if self.space
                                                      else " (signature line found)" if self.cue else "")),
                "mention": "text mention only, not used"}[self.status]
        if self.merged > 1:
            what += f" [{self.merged} adjacent places, one signature]"
        return f"page {self.page + 1}: \"{' / '.join(self.terms)}\" -> {what}"


@dataclass
class LocateOptions:
    field_radius: float = 120.0        # max distance text <-> signature field (pt)
    box_width: float = 160.0
    box_height: float = 50.0
    merge_gap: float = 200.0           # side-by-side places closer than this share one signature

    @classmethod
    def from_settings(cls, s) -> "LocateOptions":
        return cls(s.field_radius, s.box_width, s.box_height, getattr(s, "merge_gap", 200.0))


def _page_words(page) -> list[_Word]:
    ws = sorted(page.get_text("words"), key=lambda w: (w[5], w[6], w[7]))
    return [_Word(_norm(w[4]), pymupdf.Rect(w[:4]), w[4]) for w in ws]


def _has_cue(page, words: list[_Word], rect: pymupdf.Rect) -> bool:
    for wd in words:
        if _gap(wd.rect, rect) > CUE_DIST_PT:
            continue
        stripped = wd.raw.strip()
        if wd.norm in CUE_WORDS or (len(stripped) >= 5 and set(stripped) <= _LINE_CHARS):
            return True
    for d in page.get_drawings():          # drawn signature lines
        for it in d["items"]:
            if it[0] == "l":
                a, b = it[1], it[2]
                if abs(a.y - b.y) < 1.5 and abs(a.x - b.x) > 60 and \
                        _gap(pymupdf.Rect(min(a.x, b.x), a.y, max(a.x, b.x), a.y + 0.1), rect) < CUE_DIST_PT:
                    return True
    return False


def _drawn_boxes(drawings, words: list[_Word], taken: list[pymupdf.Rect]) -> list[pymupdf.Rect]:
    """Empty rectangles drawn in the page content that are signature-box sized."""
    out = []
    for dr in drawings:
        if dr.get("type") not in ("s", "fs"):
            continue
        rects = [pymupdf.Rect(it[1]) if it[0] == "re" else it[1].rect
                 for it in dr["items"] if it[0] in ("re", "qu")]
        if not rects and len(dr["items"]) == 4 and all(it[0] == "l" for it in dr["items"]):
            rects = [pymupdf.Rect(dr["rect"])]
        for r in rects:
            if not (50 <= r.width <= 350 and 18 <= r.height <= 150):
                continue
            if any(wd.norm and r.contains(pymupdf.Point((wd.rect.x0 + wd.rect.x1) / 2,
                                                        (wd.rect.y0 + wd.rect.y1) / 2)) for wd in words):
                continue                      # has text inside -> not an empty box
            if any(r.intersects(t) for t in taken):
                continue                      # already covered by a field
            out.append(r)
    return out


def _hlines(drawings) -> list[pymupdf.Rect]:
    """Horizontal rules (table borders, signature lines) as thin rectangles."""
    out = []
    for dr in drawings:
        r = dr["rect"]
        if r.height < 2 and r.width > 40:
            out.append(pymupdf.Rect(r))
        for it in dr["items"]:
            if it[0] == "l" and abs(it[1].y - it[2].y) < 1.5 and abs(it[1].x - it[2].x) > 40:
                out.append(pymupdf.Rect(min(it[1].x, it[2].x), it[1].y, max(it[1].x, it[2].x), it[1].y + 0.1))
    return out


def _fit_vertical(c: pymupdf.Rect, cy: float, blockers: list[pymupdf.Rect], min_h: float = 28) -> pymupdf.Rect:
    """Shrink a side box to the free band between the nearest blockers above and below cy."""
    xs = [b for b in blockers if b.x1 > c.x0 and b.x0 < c.x1]
    above = [b.y1 for b in xs if b.y1 <= cy and b.y1 > c.y0]
    below = [b.y0 for b in xs if b.y0 >= cy and b.y0 < c.y1]
    top = max(above) + 2 if above else c.y0
    bottom = min(below) - 2 if below else c.y1
    return pymupdf.Rect(c.x0, top, c.x1, bottom) if bottom - top >= min_h else c


def _adjacent(a: pymupdf.Rect, b: pymupdf.Rect) -> bool:
    h = max(a.height, b.height, 1.0)
    same_line = abs(a.y0 - b.y0) < 0.6 * h and -2 <= b.x0 - a.x1 < max(3 * h, 30)
    next_line = 0 < b.y0 - a.y0 < 2.5 * h and _gap(a, b) < 3 * h
    return same_line or next_line


def _variants(toks: list[str], abbrev: bool) -> list[list[str]]:
    """The name itself plus, for names, forms with every word but one cut to its initial."""
    out = [toks]
    if abbrev and len(toks) >= 2:
        for keep in range(len(toks)):
            if len(toks[keep]) > 1:
                out.append([t if i == keep else t[0] for i, t in enumerate(toks)])
    return out


def _find(words: list[_Word], term: str, any_order: bool = False) -> list[pymupdf.Rect]:
    """any_order (used for names): any word order, and initials allowed (see _variants)."""
    base = _tokens(term)
    if not base:
        return []
    orders = set()
    for toks in _variants(base, abbrev=any_order):
        orders |= set(itertools.permutations(toks)) if any_order and len(toks) <= 4 else {tuple(toks)}
    n = len(base)
    hits = []
    for i in range(len(words) - n + 1):
        if not any(all(words[i + j].norm == t for j, t in enumerate(o)) for o in orders):
            continue
        if all(_adjacent(words[i + j - 1].rect, words[i + j].rect) for j in range(1, n)):
            r = pymupdf.Rect(words[i].rect)
            for j in range(1, n):
                r |= words[i + j].rect
            if r not in hits:
                hits.append(r)
    return hits


def _signature_space(words: list[_Word], rect: pymupdf.Rect, min_space: float = 28) -> bool:
    """Typical signature block: the name stands alone on its line (no label such as
    "NAME:" right next to it) and there is free space above it to sign in."""
    real = [w for w in words if w.norm and not rect.contains(w.rect)]
    for w in real:
        v = min(w.rect.y1, rect.y1) - max(w.rect.y0, rect.y0)
        if v > 0.5 * rect.height and _gap(w.rect, rect) < 20:
            return False                       # label / other text glued to the name
    above = [w.rect.y1 for w in real if w.rect.y1 <= rect.y0 + 1
             and w.rect.x1 > rect.x0 - 10 and w.rect.x0 < rect.x1 + 10]
    return bool(above) and rect.y0 - max(above) >= min_space


def _place_box(page, anchor: pymupdf.Rect, words: list[_Word], taken: list[pymupdf.Rect],
               w: float, h: float, hlines: list[pymupdf.Rect] = ()) -> pymupdf.Rect:
    area = (page.rect * page.derotation_matrix).normalize()
    margin = 8
    cx, cy = (anchor.x0 + anchor.x1) / 2, (anchor.y0 + anchor.y1) / 2

    # keep the box inside the page's text margins (not out at the paper edge)
    xs = [wd.rect for wd in words if wd.norm]
    lo = max(area.x0 + margin, min((r.x0 for r in xs), default=area.x0) - 2)
    hi = min(area.x1 - margin, max((r.x1 for r in xs), default=area.x1) + 2)

    def clamp_x(x0):
        return max(min(x0, hi - w), lo) if hi - lo >= w else min(max(x0, area.x0 + margin), area.x1 - margin - w)

    cands = [  # preference order: above the name (typical), right, below, left
        pymupdf.Rect(clamp_x(cx - w / 2), anchor.y0 - 4 - h, clamp_x(cx - w / 2) + w, anchor.y0 - 4),
        pymupdf.Rect(anchor.x1 + 8, cy - h / 2, anchor.x1 + 8 + w, cy + h / 2),
        pymupdf.Rect(clamp_x(cx - w / 2), anchor.y1 + 4, clamp_x(cx - w / 2) + w, anchor.y1 + 4 + h),
        pymupdf.Rect(anchor.x0 - 8 - w, cy - h / 2, anchor.x0 - 8, cy + h / 2),
    ]
    # Punctuation-only "words" (dotted/underscored signature lines) may be covered.
    text = [wd.rect for wd in words if wd.norm and (wd.rect & anchor).is_empty]
    # Shrink the "above" box to the free space under the nearest text above (min 28 pt high).
    above = cands[0]
    blockers = [t.y1 for t in text if t.y1 <= anchor.y0 and t.x1 > above.x0 and t.x0 < above.x1
                and t.y1 > above.y0]
    if blockers:
        top = max(blockers) + 2
        if above.y1 - top >= 28:
            cands[0] = pymupdf.Rect(above.x0, top, above.x1, above.y1)
    # Above/below boxes: stay inside the identity's column - do not reach into the text of a
    # neighbouring name on the same line (multi-column signature blocks).
    same_line = [t for t in text if min(t.y1, anchor.y1) - max(t.y0, anchor.y0) > 0]
    left = max((t.x1 for t in same_line if t.x1 <= anchor.x0), default=None)
    right = min((t.x0 for t in same_line if t.x0 >= anchor.x1), default=None)
    for i in (0, 2):
        c = cands[i]
        # split the gap to a neighbour halfway, so adjacent signature boxes never collide
        x0 = max(c.x0, (left + anchor.x0) / 2 + 2) if left is not None else c.x0
        x1 = min(c.x1, (anchor.x1 + right) / 2 - 2) if right is not None else c.x1
        if x1 - x0 >= 60:
            cands[i] = pymupdf.Rect(x0, c.y0, x1, c.y1)
    # Side boxes: fit between the text / table rules above and below the identity text.
    for i in (1, 3):
        cands[i] = _fit_vertical(cands[i], cy, text + list(hlines))
    best, best_score, best_i = cands[0], math.inf, 0
    for i, c in enumerate(cands):
        if not area.contains(c) or any(not (c & t).is_empty for t in taken):
            continue
        overlap = sum((c & t).get_area() for t in text if not (c & t).is_empty)
        score = overlap + i * 1.0
        if score < best_score:
            best, best_score, best_i = c, score, i
    # edge of the box (PDF orientation, y up) that faces the identity text
    side = ("bottom", "left", "top", "right")[best_i] if page.rotation == 0 else "center"
    return best, side


def _side_by_side(a: pymupdf.Rect, b: pymupdf.Rect, words: list[_Word], max_gap: float) -> bool:
    """Two places on the same text line with nothing but blank space between them
    (e.g. your name under two neighbouring roles of a signature block)."""
    v = min(a.y1, b.y1) - max(a.y0, b.y0)
    if v < 0.5 * min(a.height, b.height):
        return False
    left, right = (a, b) if a.x0 <= b.x0 else (b, a)
    gap = right.x0 - left.x1
    if gap < 0 or gap > max_gap:
        return False
    band = pymupdf.Rect(left.x1, max(a.y0, b.y0), right.x0, min(a.y1, b.y1))
    return not any(w.norm and band.intersects(w.rect) and w.rect.x0 >= left.x1 - 1 and w.rect.x1 <= right.x0 + 1
                   for w in words)


def _merge(cluster: list, rect: pymupdf.Rect, term: str) -> None:
    cluster[0] |= rect
    if term not in cluster[1]:
        cluster[1].append(term)


def find_locations(pdf_path: str, identities: Identities,
                   opts: LocateOptions | None = None) -> list[Location]:
    opts = opts or LocateOptions()
    if identities.empty:
        return []
    filled = {f.name: f.filled for f in list_signature_fields(pdf_path)}
    doc = pymupdf.open(pdf_path)
    try:
        pages = []
        for page in doc:
            words = _page_words(page)
            prim = [(r, t) for t in identities.names for r in _find(words, t, any_order=True)]
            sec = [(r, t) for t in identities.roles for r in _find(words, t)]
            pages.append((page, words, prim, sec))

        locations: list[Location] = []
        for page, words, prim, sec in pages:
            anchors, extras = (prim, sec) if prim else (sec, [])
            clusters: list[list] = []          # [rect, terms]
            for r, t in sorted(anchors, key=lambda x: (x[0].y0, x[0].x0)):
                for c in clusters:
                    if _gap(c[0], r) < MERGE_GAP_PT / 2:
                        _merge(c, r, t)
                        break
                else:
                    clusters.append([pymupdf.Rect(r), [t]])
            for r, t in extras:
                for c in clusters:
                    if _gap(c[0], r) < MERGE_GAP_PT:
                        _merge(c, r, t)
                        break
            widgets = [(wd.field_name, pymupdf.Rect(wd.rect))
                       for wd in page.widgets(types=[pymupdf.PDF_WIDGET_TYPE_SIGNATURE])]
            # Side-by-side places (same line, only blank space between) get ONE signature,
            # unless each already has its own empty field.
            def own_empty(rect):
                return {n for n, wr in widgets if not filled.get(n) and wr.get_area() > 0
                        and _aligned(rect, wr) and _gap(rect, wr, xw=2.0) <= opts.field_radius}
            if opts.merge_gap > 0:
                for c in clusters:
                    c.append(1)                # number of merged places
                changed = True
                while changed:
                    changed = False
                    for i in range(len(clusters)):
                        for j in range(i + 1, len(clusters)):
                            a, b = clusters[i], clusters[j]
                            fa, fb = own_empty(a[0]), own_empty(b[0])
                            if fa and fb and fa != fb:
                                continue
                            if _side_by_side(a[0], b[0], words, opts.merge_gap):
                                for t in b[1]:
                                    _merge(a, b[0], t)
                                a[2] += b[2]
                                del clusters[j]
                                changed = True
                                break
                        if changed:
                            break
            taken = [r for _, r in widgets]
            drawings = page.get_drawings() if clusters else []
            boxes = _drawn_boxes(drawings, words, taken)
            hlines = _hlines(drawings)
            for rect, terms, *rest in clusters:
                near = [(_gap(rect, wr, xw=2.0), n, wr) for n, wr in widgets
                        if _gap(rect, wr, xw=2.0) <= opts.field_radius and wr.get_area() > 0
                        and _aligned(rect, wr)]
                loc = Location(page=page.number, text_rect=rect, terms=terms, status="new",
                               merged=rest[0] if rest else 1)
                if near:
                    _, name, wr = min(near, key=lambda x: x[0])
                    loc.status = "signed" if filled.get(name) else "field"
                    loc.field_name, loc.box = name, wr
                else:
                    drawn = [(_gap(rect, b, xw=2.0), b) for b in boxes
                             if _gap(rect, b, xw=2.0) <= opts.field_radius and _aligned(rect, b)
                             and not any(b.intersects(t) for t in taken)]
                    if drawn:
                        box = pymupdf.Rect(min(drawn, key=lambda x: x[0])[1])
                        loc.drawn = loc.cue = True
                    else:
                        box, loc.anchor = _place_box(page, rect, words, taken, opts.box_width,
                                                     opts.box_height, hlines)
                        loc.cue = _has_cue(page, words, rect)
                        if not loc.cue and terms and prim:
                            loc.cue = loc.space = _signature_space(words, rect)
                    taken.append(box)
                    loc.box = box
                    loc.box_pdf = tuple((box * ~page.transformation_matrix).normalize())
                locations.append(loc)
    finally:
        doc.close()

    # drop bare mentions when the document has better evidence somewhere
    def tier(l: Location) -> int:
        return 1 if l.status in ("field", "signed") else (2 if l.cue else 3)
    if any(tier(l) < 3 for l in locations):
        for l in locations:
            if l.status == "new" and tier(l) == 3:
                l.status = "mention"

    # one location per field; document order
    seen, out = set(), []
    for loc in sorted(locations, key=lambda l: (l.page, l.text_rect.y0, l.text_rect.x0)):
        if loc.field_name and loc.field_name in seen:
            continue
        if loc.field_name:
            seen.add(loc.field_name)
        loc.order = len(out) + 1
        out.append(loc)
    return out


def select(locations: list[Location], mode: str) -> list[Location]:
    """mode: 'first' -> first unsigned location, 'all' -> every unsigned location."""
    unsigned = [l for l in locations if l.unsigned]
    return unsigned[:1] if mode == "first" else unsigned
