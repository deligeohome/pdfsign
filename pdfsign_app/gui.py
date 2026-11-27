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
    QHBoxLayout, QInputDialog, QLabel, QLineEdit, QMainWindow, QMessageBox, QPlainTextEdit,
    QPushButton, QRadioButton, QScrollArea, QSpinBox, QSplitter, QVBoxLayout, QWidget,
)

from .config import FAILURE_MARKER, load_settings
from .signing import SignRequest, list_signature_fields
from .token import PinState, Token, WrongPinError
from .workflow import Cancelled, sign_with_token

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

    def __init__(self, req, settings, bridge):
        super().__init__()
        self.req, self.settings, self.bridge = req, settings, bridge
        bridge.word = settings.secret_word

    def run(self):
        try:
            out = sign_with_token(self.req, self.settings, self.bridge.get_pin, log=self.log.emit)
            self.done.emit(True, out)
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
    def __init__(self, pdf: str | None):
        super().__init__()
        self.settings = load_settings()
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
        if pdf:
            self.open_pdf(pdf)

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

        g = QGroupBox("Signature placement")
        gl = QVBoxLayout(g)
        self.mode_draw = QRadioButton("Draw a box on the page (drag with the mouse)")
        self.mode_field = QRadioButton("Existing empty field:")
        self.mode_invis = QRadioButton("Invisible signature")
        self.mode_draw.setChecked(True)
        self.modes = QButtonGroup(self)
        for m in (self.mode_draw, self.mode_field, self.mode_invis):
            self.modes.addButton(m)
        self.field_combo = QComboBox()
        self.field_combo.currentTextChanged.connect(self.on_field_combo)
        self.box_label = QLabel("No box drawn yet.")
        self.box_label.setWordWrap(True)
        for w in (self.mode_draw, self.box_label, self.mode_field, self.field_combo, self.mode_invis):
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
        p, _ = QFileDialog.getOpenFileName(self, "Open PDF", self.path or str(Path.home()), "PDF (*.pdf)")
        if p:
            self.open_pdf(p)

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
        field, page, box = None, 0, None
        if self.mode_draw.isChecked():
            if self.view.box is None or self.box_page is None:
                QMessageBox.information(self, "pdfsign", "Drag a rectangle on the page where the "
                                        "signature should go (or choose another placement).")
                return
            page, box = self.box_page, self.pdf_box()
        elif self.mode_field.isChecked():
            field = self.field_combo.currentText()
        src = Path(self.path)
        out, _ = QFileDialog.getSaveFileName(self, "Save signed PDF as",
                                             str(src.with_name(src.stem + "_signed.pdf")), "PDF (*.pdf)")
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
        self.worker = SignWorker(req, self.settings, self.bridge)
        self.worker.log.connect(self.say)
        self.worker.done.connect(self.on_done)
        self.worker.start()

    def on_done(self, ok: bool, msg: str):
        self.sign_btn.setEnabled(True)
        self.refresh_token()
        if ok:
            self.say(f"✔ Done: {msg}")
            if QMessageBox.question(self, "Signed", f"Signed PDF saved:\n{msg}\n\nOpen it?") == QMessageBox.Yes:
                subprocess.Popen(["xdg-open", msg])
        else:
            self.say(f"✘ {msg}")
            QMessageBox.warning(self, "Not signed", msg)


def run_gui(pdf: str | None = None):
    app = QApplication(sys.argv)
    w = MainWindow(pdf)
    w.show()
    return app.exec_()
