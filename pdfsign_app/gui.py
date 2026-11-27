"""PyQt5 GUI: open a PDF, draw (or pick) the signature box, sign with the token."""

from __future__ import annotations

import subprocess
import sys
import threading
import traceback
from pathlib import Path

import pymupdf
from PyQt5.QtCore import QObject, QPointF, QRectF, Qt, QThread, pyqtSignal
from PyQt5.QtGui import QColor, QImage, QPainter, QPen, QPixmap
from PyQt5.QtWidgets import (
    QAction, QApplication, QButtonGroup, QComboBox, QFileDialog, QFormLayout, QGroupBox,
    QHBoxLayout, QInputDialog, QLabel, QLineEdit, QListWidget, QListWidgetItem, QMainWindow,
    QMessageBox, QPlainTextEdit,
    QPushButton, QRadioButton, QScrollArea, QSpinBox, QSplitter, QVBoxLayout, QWidget,
)

from .autolocate import LocateOptions, find_locations, select
from .config import FAILURE_MARKER, ConfigError, load_settings, read_identities
from .signing import SignRequest, default_output, list_signature_fields, output_suffix
from .token import PinState, Token, WrongPinError
from .workflow import Cancelled, Job, sign_batch, sign_with_token

MIN_BOX_PT = 20  # smallest accepted signature box (points)


# ---------------------------------------------------------------------- page view
class PageView(QLabel):
    boxDrawn = pyqtSignal(QRectF)      # display-space rect, in points
    fieldClicked = pyqtSignal(str)

    def __init__(self):
        super().__init__()
        self.setAlignment(Qt.AlignLeft | Qt.AlignTop)
        self.setCursor(Qt.CrossCursor)
        self.zoom = 1.5
        self.fields: list[tuple[str, QRectF, bool]] = []   # (name, display rect pt, signed)
        self.auto: list[tuple[QRectF, str]] = []            # proposed auto-locations (rect, label)
        self.box: QRectF | None = None
        self.selected_field: str | None = None
        self._drag_start: QPointF | None = None
        self._drag_now: QPointF | None = None

    def set_page(self, pix: QPixmap, zoom: float, fields):
        self.zoom, self.fields = zoom, fields
        self.setPixmap(pix)
        self.resize(pix.size())
        self.update()

    def _pt(self, e) -> QPointF:
        return QPointF(e.pos().x() / self.zoom, e.pos().y() / self.zoom)

    def mousePressEvent(self, e):
        if e.button() != Qt.LeftButton or self.pixmap() is None:
            return
        p = self._pt(e)
        for name, r, signed in self.fields:
            if r.contains(p) and not signed:
                self.fieldClicked.emit(name)
                return
        self._drag_start = self._drag_now = p

    def mouseMoveEvent(self, e):
        if self._drag_start is not None:
            self._drag_now = self._pt(e)
            self.update()

    def mouseReleaseEvent(self, e):
        if self._drag_start is None:
            return
        r = QRectF(self._drag_start, self._pt(e)).normalized()
        self._drag_start = self._drag_now = None
        if r.width() >= MIN_BOX_PT and r.height() >= MIN_BOX_PT:
            self.boxDrawn.emit(r)
        self.update()

    def paintEvent(self, e):
        super().paintEvent(e)
        qp = QPainter(self)
        z = self.zoom
        scale = lambda r: QRectF(r.x() * z, r.y() * z, r.width() * z, r.height() * z)  # noqa: E731
        for name, r, signed in self.fields:
            col = QColor(0, 150, 0) if signed else QColor(0, 90, 220)
            if name == self.selected_field:
                col = QColor(220, 0, 0)
            qp.setPen(QPen(col, 2, Qt.DashLine))
            qp.fillRect(scale(r), QColor(col.red(), col.green(), col.blue(), 40))
            qp.drawRect(scale(r))
            qp.drawText(scale(r).adjusted(3, 2, 0, 0), Qt.AlignLeft | Qt.AlignTop,
                        f"{name}{' (signed)' if signed else ''}")
        for r, label in self.auto:
            col = QColor(255, 140, 0)
            qp.setPen(QPen(col, 3, Qt.DashDotLine))
            qp.fillRect(scale(r), QColor(255, 140, 0, 50))
            qp.drawRect(scale(r))
            qp.drawText(scale(r).adjusted(3, 0, 0, 0), Qt.AlignLeft | Qt.AlignBottom, label)
        rect = None
        if self._drag_start is not None:
            rect = QRectF(self._drag_start, self._drag_now).normalized()
        elif self.box is not None:
            rect = self.box
        if rect is not None:
            qp.setPen(QPen(QColor(220, 0, 0), 2))
            qp.fillRect(scale(rect), QColor(220, 0, 0, 40))
            qp.drawRect(scale(rect))
            qp.drawText(scale(rect).adjusted(3, 2, 0, 0), Qt.AlignLeft | Qt.AlignTop, "signature")
        qp.end()


# ---------------------------------------------------------------------- worker
class PinBridge(QObject):
    """Lets the worker thread ask the GUI thread for a PIN and wait for the answer."""
    ask = pyqtSignal(object, object)

    def __init__(self, parent):
        super().__init__(parent)
        self._event = threading.Event()
        self._answer = None
        self.word = "password"
        self.ask.connect(self._on_ask)

    def _on_ask(self, state: PinState, note):
        self._answer = ask_pin_dialog(self.parent(), state, note, self.word)
        self._event.set()

    def get_pin(self, state, note):           # called in the worker thread
        self._event.clear()
        self.ask.emit(state, note)
        self._event.wait()
        ans, self._answer = self._answer, None
        return ans


class SignWorker(QThread):
    log = pyqtSignal(str)
    done = pyqtSignal(bool, str)

    def __init__(self, req, settings, bridge, placements=None):
        super().__init__()
        self.req, self.settings, self.bridge = req, settings, bridge
        self.placements = placements
        bridge.word = settings.secret_word

    def run(self):
        try:
            out = sign_with_token(self.req, self.settings, self.bridge.get_pin, log=self.log.emit,
                                  placements=self.placements)
            self.done.emit(True, out)
        except Cancelled as e:
            self.done.emit(False, str(e))
        except WrongPinError as e:
            self.done.emit(False, f"{e}\n\nThe stored secret has been disabled ({FAILURE_MARKER}).")
        except Exception as e:  # noqa: BLE001
            self.log.emit(traceback.format_exc())
            self.done.emit(False, f"{type(e).__name__}: {e}")


class BatchWorker(QThread):
    """Signs several files with one login (workflow.sign_batch)."""
    log = pyqtSignal(str)
    done = pyqtSignal(bool, object)            # ok, list[JobResult] or error text

    def __init__(self, jobs, settings, bridge):
        super().__init__()
        self.jobs, self.settings, self.bridge = jobs, settings, bridge
        bridge.word = settings.secret_word

    def run(self):
        try:
            self.done.emit(True, sign_batch(self.jobs, self.settings, self.bridge.get_pin,
                                            log=self.log.emit))
        except Cancelled as e:
            self.done.emit(False, str(e))
        except WrongPinError as e:
            self.done.emit(False, f"{e}\n\nThe stored secret has been disabled ({FAILURE_MARKER}).")
        except Exception as e:  # noqa: BLE001
            self.log.emit(traceback.format_exc())
            self.done.emit(False, f"{type(e).__name__}: {e}")


def ask_pin_dialog(parent, state: PinState, note, word: str = "password") -> str | None:
    msg = ""
    if note:
        msg += f"Stored {word} not used:\n{note}\n\n"
    msg += f"{state.describe()}\n"
    if state.count_low or state.final_try:
        warn = (f"ONLY ONE TRY LEFT. A wrong {word} will lock the signing key PERMANENTLY."
                if state.final_try else
                f"Previous wrong attempts are recorded. Each wrong {word} brings the key closer "
                "to a PERMANENT lock.")
        if QMessageBox.warning(parent, "Retry counter is low", warn + "\n\nContinue?",
                               QMessageBox.Yes | QMessageBox.No, QMessageBox.No) != QMessageBox.Yes:
            return None
    pin, ok = QInputDialog.getText(parent, f"Digital Signature {word}",
                                   msg + f"\nEnter the Digital Signature {word}:", QLineEdit.Password)
    return pin if ok and pin else None


# ---------------------------------------------------------------------- main window
class MainWindow(QMainWindow):
    def __init__(self, pdfs: list[str] | None = None):
        super().__init__()
        self.settings = load_settings()
        self.files: list[str] = []
        self.doc = None
        self.path: str | None = None
        self.page_no = 0
        self.box_page: int | None = None
        self.worker = None
        self.bridge = PinBridge(self)
        self.setWindowTitle("pdfsign")
        self.resize(1300, 950)
        self._build_ui()
        self.refresh_token()
        if pdfs:
            self.set_files(pdfs)

    # ---- UI
    def _build_ui(self):
        tb = self.addToolBar("main")
        for text, slot, key in (("Open…", self.choose_pdf, "Ctrl+O"),
                                ("◀", lambda: self.goto(self.page_no - 1), "PgUp"),
                                ("▶", lambda: self.goto(self.page_no + 1), "PgDown")):
            a = QAction(text, self)
            a.setShortcut(key)
            a.triggered.connect(slot)
            tb.addAction(a)
        self.page_spin = QSpinBox()
        self.page_spin.setMinimum(1)
        self.page_spin.valueChanged.connect(lambda v: self.goto(v - 1))
        self.page_total = QLabel(" / 0 ")
        self.zoom_box = QComboBox()
        self.zoom_box.addItems(["75%", "100%", "125%", "150%", "200%"])
        self.zoom_box.setCurrentText("150%")
        self.zoom_box.currentTextChanged.connect(lambda _: self.render())
        for w in (QLabel(" Page "), self.page_spin, self.page_total, QLabel(" Zoom "), self.zoom_box):
            tb.addWidget(w)

        self.view = PageView()
        self.view.boxDrawn.connect(self.on_box)
        self.view.fieldClicked.connect(self.on_field_clicked)
        scroll = QScrollArea()
        scroll.setWidget(self.view)
        scroll.setAlignment(Qt.AlignCenter)

        side = QWidget()
        sv = QVBoxLayout(side)

        g = QGroupBox("Token")
        gl = QVBoxLayout(g)
        self.token_label = QLabel("…")
        self.token_label.setWordWrap(True)
        b = QPushButton("Refresh (no password/PIN used)")
        b.clicked.connect(self.refresh_token)
        row = QHBoxLayout()
        row.addWidget(QLabel("Unlock with:"))
        self.secret_type = QComboBox()
        self.secret_type.addItem("Password", "password")
        self.secret_type.addItem("PIN (digits)", "pin")
        self.secret_type.setCurrentIndex(0 if self.settings.secret_type == "password" else 1)
        row.addWidget(self.secret_type, 1)
        gl.addWidget(self.token_label)
        gl.addLayout(row)
        gl.addWidget(b)
        sv.addWidget(g)

        self.files_box = g = QGroupBox("Files")
        gl = QVBoxLayout(g)
        self.file_list = QListWidget()
        rows = self.file_list.fontMetrics().height() + 6
        self.file_list.setMinimumHeight(rows * 4)
        self.file_list.setMaximumHeight(rows * 7)
        self.file_list.setTextElideMode(Qt.ElideMiddle)
        self.file_list.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        self.file_list.currentRowChanged.connect(self.on_file_row)
        self.batch_btn = QPushButton("Sign all files (auto-locate)…")
        self.batch_btn.clicked.connect(self.sign_all)
        gl.addWidget(self.file_list)
        gl.addWidget(self.batch_btn)
        g.setVisible(False)
        sv.addWidget(g)

        g = QGroupBox("Signature placement")
        gl = QVBoxLayout(g)
        self.mode_auto = QRadioButton("Auto-locate from my identities")
        self.auto_label = QLabel("")
        self.auto_label.setWordWrap(True)
        self.auto_label.setMinimumHeight(self.auto_label.fontMetrics().height() * 2 + 4)
        self.mode_draw = QRadioButton("Draw a box on the page (drag with the mouse)")
        self.mode_field = QRadioButton("Existing empty field:")
        self.mode_invis = QRadioButton("Invisible signature")
        self.mode_draw.setChecked(True)
        self.modes = QButtonGroup(self)
        for m in (self.mode_auto, self.mode_draw, self.mode_field, self.mode_invis):
            self.modes.addButton(m)
        self.field_combo = QComboBox()
        self.field_combo.currentTextChanged.connect(self.on_field_combo)
        self.box_label = QLabel("No box drawn yet.")
        self.box_label.setWordWrap(True)
        for w in (self.mode_auto, self.auto_label, self.mode_draw, self.box_label, self.mode_field,
                  self.field_combo, self.mode_invis):
            gl.addWidget(w)
        sv.addWidget(g)

        g = QGroupBox("Details")
        fl = QFormLayout(g)
        s = self.settings
        self.reason = QLineEdit(s.reason)
        self.location = QLineEdit(s.location)
        self.contact = QLineEdit(s.contact)
        self.level = QComboBox()
        self.level.addItems(["B-T", "B-LT", "B-LTA"])
        self.level.setCurrentText(s.level)
        self.tsa = QLineEdit(s.tsa_url)
        for lab, w in (("Reason", self.reason), ("Location", self.location),
                       ("Contact", self.contact), ("PAdES level", self.level), ("TSA URL", self.tsa)):
            fl.addRow(lab, w)
        sv.addWidget(g)

        self.sign_btn = QPushButton("Sign PDF…")
        self.sign_btn.setMinimumHeight(40)
        self.sign_btn.clicked.connect(self.sign)
        sv.addWidget(self.sign_btn)
        self.log = QPlainTextEdit()
        self.log.setReadOnly(True)
        sv.addWidget(self.log, 1)

        split = QSplitter()
        split.addWidget(scroll)
        split.addWidget(side)
        side.setMinimumWidth(320)
        side.setMaximumWidth(480)
        split.setStretchFactor(0, 1)
        split.setStretchFactor(1, 0)
        split.setSizes([900, 400])
        self.setCentralWidget(split)

    def say(self, text: str):
        self.log.appendPlainText(text)

    # ---- token
    def refresh_token(self):
        try:
            t = Token.from_settings(self.settings)
            self.cert = t.certificate
            st = t.pin_state()
            txt = f"<b>{t.signer_name}</b><br>{t.certificate.issuer.native.get('common_name', '')}<br>{st.describe()}"
            if st.count_low or st.locked:
                txt = f"<span style='color:#c00'>{txt}</span>"
            if FAILURE_MARKER.exists():
                txt += "<br><span style='color:#c00'>Stored password/PIN disabled after a rejected attempt.</span>"
            self.token_label.setText(txt)
            t.close()
        except Exception as e:  # noqa: BLE001
            self.token_label.setText(f"<span style='color:#c00'>{e}</span>")

    # ---- document
    def choose_pdf(self):
        start = str(Path(self.path).parent) if self.path else str(Path.home())
        ps, _ = QFileDialog.getOpenFileNames(self, "Open PDF(s)", start, "PDF (*.pdf)")
        if ps:
            self.set_files(ps)

    def set_files(self, paths: list[str]):
        """One file: plain viewer. Several: file list + 'Sign all files'."""
        self.files = [str(Path(p).resolve()) for p in paths]
        self.files_box.setVisible(len(self.files) > 1)
        self.file_list.blockSignals(True)
        self.file_list.clear()
        if len(self.files) > 1:
            self.files_box.setTitle(f"Files ({len(self.files)})")
            ids = self._identities()
            for p in self.files:
                it = QListWidgetItem(f"[{self._status(p, ids)}]  {Path(p).name}")
                it.setToolTip(p)
                self.file_list.addItem(it)
        self.file_list.blockSignals(False)
        self.file_list.setCurrentRow(0)
        self.open_pdf(self.files[0])

    def _identities(self):
        try:
            ids = read_identities()
            return None if ids.empty else ids
        except ConfigError:
            return None

    def _status(self, path: str, ids) -> str:
        if ids is None:
            return "no identities"
        try:
            locs = find_locations(path, ids, LocateOptions.from_settings(self.settings))
        except Exception as e:  # noqa: BLE001
            return f"error: {e}"
        todo = sum(l.unsigned for l in locs)
        done = sum(l.status == "signed" for l in locs)
        return f"{todo} to sign" if todo else ("signed" if done else "not found")

    def on_file_row(self, row: int):
        if 0 <= row < len(self.files) and self.files[row] != self.path:
            self.open_pdf(self.files[row])

    def open_pdf(self, path: str):
        try:
            doc = pymupdf.open(path)
            if doc.needs_pass:
                raise ValueError("Encrypted PDFs are not supported.")
        except Exception as e:  # noqa: BLE001
            QMessageBox.critical(self, "Open failed", str(e))
            return
        self.doc, self.path = doc, path
        self.view.box, self.box_page, self.view.selected_field = None, None, None
        self.box_label.setText("No box drawn yet.")
        self.page_spin.setMaximum(doc.page_count)
        self.page_total.setText(f" / {doc.page_count} ")
        self.setWindowTitle(f"pdfsign — {Path(path).name}")
        self.sig_fields = {f.name: f.filled for f in list_signature_fields(path)}
        self.field_combo.blockSignals(True)
        self.field_combo.clear()
        self.field_combo.addItems([n for n, filled in self.sig_fields.items() if not filled])
        self.field_combo.blockSignals(False)
        self.mode_field.setEnabled(self.field_combo.count() > 0)
        if self.sig_fields:
            self.say(f"Signature fields: " + ", ".join(
                f"{n} ({'signed' if f else 'empty'})" for n, f in self.sig_fields.items()))
        self.auto_locate()

    def auto_locate(self):
        self.locations = []
        try:
            ids = read_identities()
            if not ids.empty:
                self.locations = find_locations(self.path, ids, LocateOptions.from_settings(self.settings))
        except ConfigError as e:
            self.say(f"Identities not read: {e}")
            ids = None
        unsigned = [l for l in self.locations if l.unsigned]
        if ids is None or ids.empty:
            self.auto_label.setText("No [identities] in credentials.ini.")
        elif not self.locations:
            self.auto_label.setText("Your identities were not found in this document.")
        else:
            done = sum(l.status == "signed" for l in self.locations)
            self.auto_label.setText(f"{len(unsigned)} to sign (orange), {done} signed")
            self.say("Identity locations:\n" + "\n".join(
                f"  {'->' if l.unsigned else '  '} #{l.order} {l.describe()}" for l in self.locations))
        self.mode_auto.setEnabled(bool(unsigned))
        if unsigned:
            self.mode_auto.setChecked(True)
            self.goto(unsigned[0].page)
        else:
            self.mode_draw.setChecked(True)
            self.goto(0)

    def goto(self, n: int):
        if not self.doc or not 0 <= n < self.doc.page_count:
            return
        self.page_no = n
        self.page_spin.blockSignals(True)
        self.page_spin.setValue(n + 1)
        self.page_spin.blockSignals(False)
        self.render()

    def render(self):
        if not self.doc:
            return
        page = self.doc[self.page_no]
        zoom = int(self.zoom_box.currentText().rstrip("%")) / 100
        pix = page.get_pixmap(matrix=pymupdf.Matrix(zoom, zoom), alpha=False)
        img = QImage(pix.samples, pix.width, pix.height, pix.stride, QImage.Format_RGB888).copy()
        fields = []
        for w in page.widgets(types=[pymupdf.PDF_WIDGET_TYPE_SIGNATURE]):
            r = w.rect * page.rotation_matrix
            fields.append((w.field_name, QRectF(r.x0, r.y0, r.width, r.height),
                           self.sig_fields.get(w.field_name, False)))
        self.view.auto = []
        for l in getattr(self, "locations", []):
            if l.page == self.page_no and l.unsigned:
                r = l.box * page.rotation_matrix
                self.view.auto.append((QRectF(r.x0, r.y0, r.width, r.height), f"auto #{l.order}"))
        self.view.box = self.view.box if self.box_page == self.page_no else None
        self.view.set_page(QPixmap.fromImage(img), zoom, fields)

    # ---- placement
    def on_box(self, r: QRectF):
        self.view.box, self.box_page = r, self.page_no
        self.view.selected_field = None
        self.mode_draw.setChecked(True)
        x1, y1, x2, y2 = self.pdf_box()
        self.box_label.setText(f"Page {self.page_no + 1}, box ({x1:.0f}, {y1:.0f}) – ({x2:.0f}, {y2:.0f}) pt")
        self.view.update()

    def on_field_clicked(self, name: str):
        self.field_combo.setCurrentText(name)
        self.on_field_combo(name)

    def on_field_combo(self, name: str):
        if not name:
            return
        self.mode_field.setChecked(True)
        self.view.selected_field = name
        self.view.box = None
        self.view.update()

    def pdf_box(self):
        page = self.doc[self.box_page]
        b = self.view.box
        disp = pymupdf.Rect(b.left(), b.top(), b.right(), b.bottom())
        r = (disp * page.derotation_matrix * ~page.transformation_matrix).normalize()
        return (r.x0, r.y0, r.x1, r.y1)

    # ---- signing
    def sign(self):
        if not self.doc:
            QMessageBox.information(self, "pdfsign", "Open a PDF first.")
            return
        field, page, box, placements = None, 0, None, None
        if self.mode_auto.isChecked():
            unsigned = [l for l in self.locations if l.unsigned]
            if not unsigned:
                QMessageBox.information(self, "pdfsign", "No unsigned identity location.")
                return
            mode = "first"
            if len(unsigned) > 1:
                mb = QMessageBox(QMessageBox.Question, "Several signature places",
                                 f"Your identity appears at {len(unsigned)} unsigned places:\n\n" +
                                 "\n".join(f"#{l.order}  {l.describe()}" for l in unsigned) +
                                 "\n\nSign only the first one, or all of them?", parent=self)
                b_first = mb.addButton(f"First (#{unsigned[0].order}, page {unsigned[0].page + 1})",
                                       QMessageBox.AcceptRole)
                b_all = mb.addButton(f"All {len(unsigned)}", QMessageBox.AcceptRole)
                mb.addButton(QMessageBox.Cancel)
                mb.exec_()
                if mb.clickedButton() not in (b_first, b_all):
                    return
                mode = "all" if mb.clickedButton() is b_all else "first"
            chosen = select(self.locations, mode)
            placements = [l.placement() for l in chosen]
            self.say("Auto placement: " + ", ".join(f"#{l.order} (page {l.page + 1})" for l in chosen))
        elif self.mode_draw.isChecked():
            if self.view.box is None or self.box_page is None:
                QMessageBox.information(self, "pdfsign", "Drag a rectangle on the page where the "
                                        "signature should go (or choose another placement).")
                return
            page, box = self.box_page, self.pdf_box()
        elif self.mode_field.isChecked():
            field = self.field_combo.currentText()
        src = Path(self.path)
        suggested = default_output(self.path, output_suffix(self.settings, getattr(self, "cert", None)))
        out, _ = QFileDialog.getSaveFileName(self, "Save signed PDF as", suggested, "PDF (*.pdf)")
        if not out:
            return
        if Path(out).resolve() == src.resolve():
            QMessageBox.warning(self, "pdfsign", "Choose a different file name; the original is kept intact.")
            return
        self.settings.tsa_url = self.tsa.text().strip()
        self.settings.secret_type = self.secret_type.currentData()
        req = SignRequest(self.path, out, field_name=field, page=page, box=box,
                          reason=self.reason.text().strip(), location=self.location.text().strip(),
                          contact=self.contact.text().strip(), level=self.level.currentText())
        self.sign_btn.setEnabled(False)
        self.worker = SignWorker(req, self.settings, self.bridge, placements)
        self.worker.log.connect(self.say)
        self.worker.done.connect(self.on_done)
        self.worker.start()

    def sign_all(self):
        """Auto-locate and sign every listed file; outputs next to each input; one login."""
        ids = self._identities()
        if ids is None:
            QMessageBox.information(self, "pdfsign", "Batch signing needs [identities] in credentials.ini.")
            return
        opts = LocateOptions.from_settings(self.settings)
        located = [(p, find_locations(p, ids, opts)) for p in self.files]
        todo = [(p, locs) for p, locs in located if any(l.unsigned for l in locs)]
        skipped = [Path(p).name for p, locs in located if not any(l.unsigned for l in locs)]
        if not todo:
            QMessageBox.information(self, "pdfsign", "Nothing to sign: your identities are already "
                                    "signed or not found in these files.")
            return
        mode = "first"
        multi = [p for p, locs in todo if sum(l.unsigned for l in locs) > 1]
        if multi:
            mb = QMessageBox(QMessageBox.Question, "Several signature places",
                             f"{len(multi)} of the files have several unsigned places for you:\n\n" +
                             "\n".join(Path(p).name for p in multi) +
                             "\n\nIn those files, sign only the first place or all of them?", parent=self)
            b_first = mb.addButton("First", QMessageBox.AcceptRole)
            b_all = mb.addButton("All", QMessageBox.AcceptRole)
            mb.addButton(QMessageBox.Cancel)
            mb.exec_()
            if mb.clickedButton() not in (b_first, b_all):
                return
            mode = "all" if mb.clickedButton() is b_all else "first"
        suffix = output_suffix(self.settings, getattr(self, "cert", None))
        self.settings.tsa_url = self.tsa.text().strip()
        self.settings.secret_type = self.secret_type.currentData()
        jobs, lines = [], []
        for p, locs in todo:
            chosen = select(locs, mode)
            out = default_output(p, suffix)
            jobs.append(Job(SignRequest(p, out, reason=self.reason.text().strip(),
                                        location=self.location.text().strip(),
                                        contact=self.contact.text().strip(),
                                        level=self.level.currentText()),
                            [l.placement() for l in chosen]))
            lines.append(f"{Path(p).name}  ({len(chosen)}×)  →  {Path(out).name}")
        text = f"Sign {len(jobs)} file(s)? Signed copies are saved next to the originals:\n\n" + "\n".join(lines)
        if skipped:
            text += "\n\nNothing to sign in: " + ", ".join(skipped)
        if QMessageBox.question(self, "Sign all files", text) != QMessageBox.Yes:
            return
        self.sign_btn.setEnabled(False)
        self.batch_btn.setEnabled(False)
        self.worker = BatchWorker(jobs, self.settings, self.bridge)
        self.worker.log.connect(self.say)
        self.worker.done.connect(self.on_batch_done)
        self.worker.start()

    def on_batch_done(self, ok: bool, res):
        self.sign_btn.setEnabled(True)
        self.batch_btn.setEnabled(True)
        self.refresh_token()
        if not ok:
            self.say(f"✘ {res}")
            QMessageBox.warning(self, "Not signed", res)
            return
        good = [r for r in res if r.output]
        bad = [r for r in res if r.error]
        lines = [f"✔ {Path(r.output).name}" for r in good] + \
                [f"✘ {Path(r.job.req.input_pdf).name}: {r.error}" for r in bad]
        self.say("Batch finished:\n  " + "\n  ".join(lines))
        mb = QMessageBox(QMessageBox.Information if not bad else QMessageBox.Warning, "Batch signed",
                         f"{len(good)} signed, {len(bad)} failed.\n\n" + "\n".join(lines), parent=self)
        b_load = mb.addButton("Load signed files", QMessageBox.AcceptRole) if good else None
        mb.addButton(QMessageBox.Close)
        mb.exec_()
        if good and mb.clickedButton() is b_load:
            self.set_files([r.output for r in good])

    def on_done(self, ok: bool, msg: str):
        self.sign_btn.setEnabled(True)
        self.refresh_token()
        if ok:
            self.say(f"✔ Done: {msg}")
            mb = QMessageBox(QMessageBox.Information, "Signed", f"Signed PDF saved:\n{msg}", parent=self)
            b_view = mb.addButton("Open in PDF viewer", QMessageBox.AcceptRole)
            b_load = mb.addButton("Load here (next step)", QMessageBox.AcceptRole)
            mb.addButton(QMessageBox.Close)
            mb.exec_()
            if mb.clickedButton() is b_view:
                subprocess.Popen(["xdg-open", msg])
            elif mb.clickedButton() is b_load:
                if len(self.files) > 1 and self.path in self.files:
                    # replace the original by its signed copy in the file list
                    row = self.files.index(self.path)
                    self.files[row] = str(Path(msg).resolve())
                    self.file_list.blockSignals(True)
                    self.file_list.item(row).setText(
                        f"[{self._status(msg, self._identities())}]  {Path(msg).name}")
                    self.file_list.item(row).setToolTip(msg)
                    self.file_list.blockSignals(False)
                    self.open_pdf(self.files[row])
                else:
                    self.set_files([msg])
        else:
            self.say(f"✘ {msg}")
            QMessageBox.warning(self, "Not signed", msg)


def run_gui(pdfs: list[str] | None = None):
    app = QApplication(sys.argv)
    w = MainWindow(pdfs)
    w.show()
    return app.exec_()
