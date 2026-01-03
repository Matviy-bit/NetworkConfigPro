"""Theme and styling for PySide6 GUI."""

# Color palette - Professional dark theme
COLORS = {
    "background": "#0f172a",
    "surface": "#1e293b",
    "surface_light": "#334155",
    "primary": "#2563eb",
    "primary_hover": "#1d4ed8",
    "secondary": "#64748b",
    "secondary_hover": "#475569",
    "success": "#10b981",
    "success_hover": "#059669",
    "warning": "#f59e0b",
    "warning_hover": "#d97706",
    "error": "#ef4444",
    "error_hover": "#dc2626",
    "info": "#06b6d4",
    "text_primary": "#f8fafc",
    "text_secondary": "#94a3b8",
    "text_muted": "#64748b",
    "border": "#475569",
}

# Dark stylesheet for Qt
DARK_STYLESHEET = f"""
QMainWindow {{
    background-color: {COLORS["background"]};
}}

QWidget {{
    background-color: {COLORS["background"]};
    color: {COLORS["text_primary"]};
    font-family: "Segoe UI", "SF Pro Display", -apple-system, sans-serif;
    font-size: 13px;
}}

QTabWidget::pane {{
    background-color: {COLORS["surface"]};
    border: 1px solid {COLORS["border"]};
    border-radius: 8px;
    padding: 8px;
}}

QTabBar::tab {{
    background-color: {COLORS["surface_light"]};
    color: {COLORS["text_secondary"]};
    padding: 10px 24px;
    margin-right: 2px;
    border-top-left-radius: 6px;
    border-top-right-radius: 6px;
    font-weight: 500;
}}

QTabBar::tab:selected {{
    background-color: {COLORS["primary"]};
    color: {COLORS["text_primary"]};
}}

QTabBar::tab:hover:!selected {{
    background-color: {COLORS["secondary"]};
    color: {COLORS["text_primary"]};
}}

QFrame {{
    background-color: {COLORS["surface"]};
    border-radius: 8px;
}}

QFrame#card {{
    background-color: {COLORS["surface"]};
    border: 1px solid {COLORS["border"]};
    border-radius: 8px;
    padding: 12px;
}}

QLabel {{
    background-color: transparent;
    color: {COLORS["text_primary"]};
}}

QLabel#title {{
    font-size: 20px;
    font-weight: bold;
    color: {COLORS["primary"]};
}}

QLabel#heading {{
    font-size: 16px;
    font-weight: bold;
}}

QLabel#secondary {{
    color: {COLORS["text_secondary"]};
    font-size: 12px;
}}

QLabel#instructions {{
    color: {COLORS["text_secondary"]};
    font-size: 13px;
    padding: 12px 16px;
    background-color: {COLORS["surface"]};
    border-left: 3px solid {COLORS["primary"]};
    border-radius: 4px;
    line-height: 1.5;
}}

QLineEdit {{
    background-color: {COLORS["surface_light"]};
    border: 1px solid {COLORS["border"]};
    border-radius: 6px;
    padding: 10px 12px;
    color: {COLORS["text_primary"]};
    selection-background-color: {COLORS["primary"]};
    font-size: 13px;
}}

QLineEdit:focus {{
    border: 2px solid {COLORS["primary"]};
    padding: 9px 11px;
}}

QLineEdit:disabled {{
    background-color: {COLORS["secondary"]};
    color: {COLORS["text_muted"]};
}}

QTextEdit, QPlainTextEdit {{
    background-color: {COLORS["surface_light"]};
    border: 1px solid {COLORS["border"]};
    border-radius: 6px;
    padding: 10px;
    color: {COLORS["text_primary"]};
    font-family: "JetBrains Mono", "Fira Code", "Consolas", "Monaco", monospace;
    font-size: 12px;
    selection-background-color: {COLORS["primary"]};
}}

QTextEdit:focus, QPlainTextEdit:focus {{
    border: 2px solid {COLORS["primary"]};
    padding: 9px;
}}

QPushButton {{
    background-color: {COLORS["primary"]};
    color: {COLORS["text_primary"]};
    border: none;
    border-radius: 6px;
    padding: 10px 20px;
    font-weight: 600;
    font-size: 13px;
    border: 2px solid transparent;
}}

QPushButton:hover {{
    background-color: {COLORS["primary_hover"]};
    border: 2px solid rgba(255, 255, 255, 0.2);
}}

QPushButton:pressed {{
    background-color: #1e3a8a;
    border: 2px solid {COLORS["primary"]};
    padding: 12px 18px;
    margin: -2px 2px 2px -2px;
}}

QPushButton:disabled {{
    background-color: {COLORS["secondary"]};
    color: {COLORS["text_muted"]};
}}

QPushButton#secondary {{
    background-color: {COLORS["secondary"]};
    border: 2px solid transparent;
}}

QPushButton#secondary:hover {{
    background-color: {COLORS["secondary_hover"]};
    border: 2px solid rgba(255, 255, 255, 0.15);
}}

QPushButton#secondary:pressed {{
    background-color: #374151;
    border: 2px solid {COLORS["secondary"]};
    padding: 12px 18px;
    margin: -2px 2px 2px -2px;
}}

QPushButton#success {{
    background-color: {COLORS["success"]};
    border: 2px solid transparent;
}}

QPushButton#success:hover {{
    background-color: {COLORS["success_hover"]};
    border: 2px solid rgba(255, 255, 255, 0.2);
}}

QPushButton#success:pressed {{
    background-color: #047857;
    border: 2px solid {COLORS["success"]};
    padding: 12px 18px;
    margin: -2px 2px 2px -2px;
}}

QPushButton#nav {{
    background-color: transparent;
    text-align: left;
    padding: 12px 16px;
    border-radius: 6px;
    font-size: 14px;
    font-weight: normal;
    border: 2px solid transparent;
}}

QPushButton#nav:hover {{
    background-color: {COLORS["surface_light"]};
    border: 2px solid rgba(255, 255, 255, 0.1);
}}

QPushButton#nav:pressed {{
    background-color: {COLORS["primary"]};
    border: 2px solid rgba(255, 255, 255, 0.3);
    padding: 14px 14px;
    margin: -2px 2px 2px -2px;
}}

QPushButton#nav:checked {{
    background-color: {COLORS["primary"]};
    font-weight: 600;
    border: 2px solid rgba(255, 255, 255, 0.15);
}}

QComboBox {{
    background-color: {COLORS["surface_light"]};
    border: 1px solid {COLORS["border"]};
    border-radius: 6px;
    padding: 10px 12px;
    color: {COLORS["text_primary"]};
    min-width: 180px;
    font-size: 13px;
}}

QComboBox:hover {{
    border: 1px solid {COLORS["primary"]};
}}

QComboBox:focus {{
    border: 2px solid {COLORS["primary"]};
    padding: 9px 11px;
}}

QComboBox::drop-down {{
    border: none;
    width: 30px;
}}

QComboBox::down-arrow {{
    image: none;
    border-left: 5px solid transparent;
    border-right: 5px solid transparent;
    border-top: 6px solid {COLORS["text_secondary"]};
    margin-right: 10px;
}}

QComboBox QAbstractItemView {{
    background-color: {COLORS["surface"]};
    border: 1px solid {COLORS["border"]};
    border-radius: 6px;
    selection-background-color: {COLORS["primary"]};
    color: {COLORS["text_primary"]};
    padding: 4px;
    outline: none;
}}

QComboBox QAbstractItemView::item {{
    padding: 8px 12px;
    border-radius: 4px;
}}

QComboBox QAbstractItemView::item:hover {{
    background-color: {COLORS["surface_light"]};
}}

QScrollArea {{
    background-color: transparent;
    border: none;
}}

QScrollArea > QWidget > QWidget {{
    background-color: transparent;
}}

QScrollBar:vertical {{
    background-color: {COLORS["surface"]};
    width: 10px;
    border-radius: 5px;
    margin: 0;
}}

QScrollBar::handle:vertical {{
    background-color: {COLORS["surface_light"]};
    border-radius: 5px;
    min-height: 30px;
}}

QScrollBar::handle:vertical:hover {{
    background-color: {COLORS["secondary"]};
}}

QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {{
    height: 0px;
}}

QScrollBar::add-page:vertical, QScrollBar::sub-page:vertical {{
    background: none;
}}

QScrollBar:horizontal {{
    background-color: {COLORS["surface"]};
    height: 10px;
    border-radius: 5px;
    margin: 0;
}}

QScrollBar::handle:horizontal {{
    background-color: {COLORS["surface_light"]};
    border-radius: 5px;
    min-width: 30px;
}}

QScrollBar::handle:horizontal:hover {{
    background-color: {COLORS["secondary"]};
}}

QScrollBar::add-line:horizontal, QScrollBar::sub-line:horizontal {{
    width: 0px;
}}

QScrollBar::add-page:horizontal, QScrollBar::sub-page:horizontal {{
    background: none;
}}

QStatusBar {{
    background-color: {COLORS["surface"]};
    color: {COLORS["text_secondary"]};
    border-top: 1px solid {COLORS["border"]};
    padding: 4px 12px;
    font-size: 12px;
}}

QSplitter::handle {{
    background-color: {COLORS["border"]};
}}

QSplitter::handle:horizontal {{
    width: 1px;
}}

QSplitter::handle:vertical {{
    height: 1px;
}}

QGroupBox {{
    background-color: {COLORS["surface"]};
    border: 1px solid {COLORS["border"]};
    border-radius: 8px;
    margin-top: 24px;
    padding: 16px;
    padding-top: 12px;
    font-weight: bold;
}}

QGroupBox::title {{
    subcontrol-origin: margin;
    subcontrol-position: top left;
    padding: 4px 12px;
    margin-left: 8px;
    color: {COLORS["text_primary"]};
    background-color: transparent;
    font-size: 13px;
    font-weight: 600;
}}
"""

# Sidebar specific style
SIDEBAR_STYLE = f"""
QFrame#sidebar {{
    background-color: {COLORS["surface"]};
    border-right: 1px solid {COLORS["border"]};
    border-radius: 0px;
}}
"""
