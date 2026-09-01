"""
Generador gráfico nativo de tarjetas de seguridad en formato PNG (Pure Python).
Dibuja tarjetas visuales con cabeceras de color según severidad/acción,
insignias (badges), tablas estructuradas de información, bloques de diagnóstico y pie de página.
No requiere dependencias externas ni bibliotecas C, funciona 100% en AWS Lambda.
"""
import io
import struct
import zlib

# Fuente de mapa de bits 5x7 estándar para caracteres ASCII imprimibles (32 a 126)
FONT_5x7 = {
    ' ': [0x00, 0x00, 0x00, 0x00, 0x00],
    '!': [0x00, 0x00, 0x5F, 0x00, 0x00],
    '"': [0x00, 0x07, 0x00, 0x07, 0x00],
    '#': [0x14, 0x7F, 0x14, 0x7F, 0x14],
    '$': [0x24, 0x2A, 0x7F, 0x2A, 0x12],
    '%': [0x23, 0x13, 0x08, 0x64, 0x62],
    '&': [0x36, 0x49, 0x55, 0x22, 0x50],
    "'": [0x00, 0x05, 0x03, 0x00, 0x00],
    '(': [0x00, 0x1C, 0x22, 0x41, 0x00],
    ')': [0x00, 0x41, 0x22, 0x1C, 0x00],
    '*': [0x14, 0x08, 0x3E, 0x08, 0x14],
    '+': [0x08, 0x08, 0x3E, 0x08, 0x08],
    ',': [0x00, 0x50, 0x30, 0x00, 0x00],
    '-': [0x08, 0x08, 0x08, 0x08, 0x08],
    '.': [0x00, 0x60, 0x60, 0x00, 0x00],
    '/': [0x20, 0x10, 0x08, 0x04, 0x02],
    '0': [0x3E, 0x51, 0x49, 0x45, 0x3E],
    '1': [0x00, 0x42, 0x7F, 0x40, 0x00],
    '2': [0x42, 0x61, 0x51, 0x49, 0x46],
    '3': [0x21, 0x41, 0x45, 0x4B, 0x31],
    '4': [0x18, 0x14, 0x12, 0x7F, 0x10],
    '5': [0x27, 0x45, 0x45, 0x45, 0x39],
    '6': [0x3C, 0x4A, 0x49, 0x49, 0x30],
    '7': [0x01, 0x71, 0x09, 0x05, 0x03],
    '8': [0x36, 0x49, 0x49, 0x49, 0x36],
    '9': [0x06, 0x49, 0x49, 0x29, 0x1E],
    ':': [0x00, 0x36, 0x36, 0x00, 0x00],
    ';': [0x00, 0x56, 0x36, 0x00, 0x00],
    '<': [0x08, 0x14, 0x22, 0x41, 0x00],
    '=': [0x14, 0x14, 0x14, 0x14, 0x14],
    '>': [0x00, 0x41, 0x22, 0x14, 0x08],
    '?': [0x02, 0x01, 0x51, 0x09, 0x06],
    '@': [0x32, 0x49, 0x79, 0x41, 0x3E],
    'A': [0x7E, 0x11, 0x11, 0x11, 0x7E],
    'B': [0x7F, 0x49, 0x49, 0x49, 0x36],
    'C': [0x3E, 0x41, 0x41, 0x41, 0x22],
    'D': [0x7F, 0x41, 0x41, 0x22, 0x1C],
    'E': [0x7F, 0x49, 0x49, 0x49, 0x41],
    'F': [0x7F, 0x09, 0x09, 0x09, 0x01],
    'G': [0x3E, 0x41, 0x49, 0x49, 0x7A],
    'H': [0x7F, 0x08, 0x08, 0x08, 0x7F],
    'I': [0x00, 0x41, 0x7F, 0x41, 0x00],
    'J': [0x20, 0x40, 0x41, 0x3F, 0x01],
    'K': [0x7F, 0x08, 0x14, 0x22, 0x41],
    'L': [0x7F, 0x40, 0x40, 0x40, 0x40],
    'M': [0x7F, 0x02, 0x0C, 0x02, 0x7F],
    'N': [0x7F, 0x04, 0x08, 0x10, 0x7F],
    'O': [0x3E, 0x41, 0x41, 0x41, 0x3E],
    'P': [0x7F, 0x09, 0x09, 0x09, 0x06],
    'Q': [0x3E, 0x41, 0x51, 0x21, 0x5E],
    'R': [0x7F, 0x09, 0x19, 0x29, 0x46],
    'S': [0x46, 0x49, 0x49, 0x49, 0x31],
    'T': [0x01, 0x01, 0x7F, 0x01, 0x01],
    'U': [0x3F, 0x40, 0x40, 0x40, 0x3F],
    'V': [0x1F, 0x20, 0x40, 0x20, 0x1F],
    'W': [0x3F, 0x40, 0x38, 0x40, 0x3F],
    'X': [0x63, 0x14, 0x08, 0x14, 0x63],
    'Y': [0x07, 0x08, 0x70, 0x08, 0x07],
    'Z': [0x61, 0x51, 0x49, 0x45, 0x43],
    '[': [0x00, 0x7F, 0x41, 0x41, 0x00],
    '\\': [0x02, 0x04, 0x08, 0x10, 0x20],
    ']': [0x00, 0x41, 0x41, 0x7F, 0x00],
    '^': [0x04, 0x02, 0x01, 0x02, 0x04],
    '_': [0x40, 0x40, 0x40, 0x40, 0x40],
    '`': [0x00, 0x01, 0x02, 0x04, 0x00],
    'a': [0x20, 0x54, 0x54, 0x54, 0x78],
    'b': [0x7F, 0x48, 0x44, 0x44, 0x38],
    'c': [0x38, 0x44, 0x44, 0x44, 0x20],
    'd': [0x38, 0x44, 0x44, 0x48, 0x7F],
    'e': [0x38, 0x54, 0x54, 0x54, 0x18],
    'f': [0x08, 0x7E, 0x09, 0x01, 0x02],
    'g': [0x0C, 0x52, 0x52, 0x52, 0x3E],
    'h': [0x7F, 0x08, 0x04, 0x04, 0x78],
    'i': [0x00, 0x44, 0x7D, 0x40, 0x00],
    'j': [0x20, 0x40, 0x44, 0x3D, 0x00],
    'k': [0x7F, 0x10, 0x28, 0x44, 0x00],
    'l': [0x00, 0x41, 0x7F, 0x40, 0x00],
    'm': [0x7C, 0x04, 0x18, 0x04, 0x78],
    'n': [0x7C, 0x08, 0x04, 0x04, 0x78],
    'o': [0x38, 0x44, 0x44, 0x44, 0x38],
    'p': [0x7C, 0x14, 0x14, 0x14, 0x08],
    'q': [0x08, 0x14, 0x14, 0x18, 0x7C],
    'r': [0x7C, 0x08, 0x04, 0x04, 0x08],
    's': [0x48, 0x54, 0x54, 0x54, 0x20],
    't': [0x04, 0x3F, 0x44, 0x40, 0x20],
    'u': [0x3C, 0x40, 0x40, 0x20, 0x7C],
    'v': [0x1C, 0x20, 0x40, 0x20, 0x1C],
    'w': [0x3C, 0x40, 0x30, 0x40, 0x3C],
    'x': [0x44, 0x28, 0x10, 0x28, 0x44],
    'y': [0x0C, 0x50, 0x50, 0x50, 0x3C],
    'z': [0x44, 0x64, 0x54, 0x4C, 0x44],
    '{': [0x00, 0x08, 0x36, 0x41, 0x00],
    '|': [0x00, 0x00, 0x7F, 0x00, 0x00],
    '}': [0x00, 0x41, 0x36, 0x08, 0x00],
    '~': [0x08, 0x04, 0x08, 0x10, 0x08],
}


class Canvas:
    def __init__(self, width: int, height: int, bg_color=(244, 246, 248)):
        self.width = width
        self.height = height
        self.bg_color = bg_color
        # Buffer de píxeles: lista plana de tuplas (R, G, B)
        self.pixels = [bg_color] * (width * height)

    def set_pixel(self, x: int, y: int, color: tuple):
        if 0 <= x < self.width and 0 <= y < self.height:
            self.pixels[y * self.width + x] = color

    def fill_rect(self, x: int, y: int, w: int, h: int, color: tuple):
        x1 = max(0, x)
        y1 = max(0, y)
        x2 = min(self.width, x + w)
        y2 = min(self.height, y + h)
        for cy in range(y1, y2):
            row_start = cy * self.width
            for cx in range(x1, x2):
                self.pixels[row_start + cx] = color

    def draw_rect(self, x: int, y: int, w: int, h: int, border_color: tuple, border_width: int = 1):
        # Top and bottom
        self.fill_rect(x, y, w, border_width, border_color)
        self.fill_rect(x, y + h - border_width, w, border_width, border_color)
        # Left and right
        self.fill_rect(x, y, border_width, h, border_color)
        self.fill_rect(x + w - border_width, y, border_width, h, border_color)

    def draw_char(self, x: int, y: int, char: str, color: tuple, scale: int = 2):
        glyph = FONT_5x7.get(char, FONT_5x7.get('?'))
        for col_idx, col_byte in enumerate(glyph):
            for row_idx in range(7):
                if (col_byte >> row_idx) & 1:
                    px = x + col_idx * scale
                    py = y + row_idx * scale
                    self.fill_rect(px, py, scale, scale, color)

    def draw_text(self, x: int, y: int, text: str, color: tuple, scale: int = 2) -> int:
        cur_x = x
        char_width = 6 * scale
        for char in str(text):
            if char == '\n':
                y += 9 * scale
                cur_x = x
                continue
            self.draw_char(cur_x, y, char, color, scale)
            cur_x += char_width
        return cur_x

    def draw_text_wrapped(self, x: int, y: int, text: str, max_w: int, color: tuple, scale: int = 2) -> int:
        words = str(text).split(' ')
        cur_x = x
        cur_y = y
        char_w = 6 * scale
        line_h = 9 * scale

        for word in words:
            word_w = len(word) * char_w
            if cur_x + word_w > x + max_w and cur_x > x:
                cur_y += line_h
                cur_x = x
            for char in word:
                self.draw_char(cur_x, cur_y, char, color, scale)
                cur_x += char_w
            cur_x += char_w  # Space

        return cur_y + line_h

    def to_png_bytes(self) -> bytes:
        raw_data = bytearray()
        for y in range(self.height):
            raw_data.append(0)  # Filter byte 0 (None)
            row_start = y * self.width
            for x in range(self.width):
                r, g, b = self.pixels[row_start + x]
                raw_data.extend((r, g, b, 255))  # RGBA

        compressed = zlib.compress(bytes(raw_data), 1)

        out = bytearray(b'\x89PNG\r\n\x1a\n')

        # IHDR
        ihdr_data = struct.pack('>IIBBBBB', self.width, self.height, 8, 6, 0, 0, 0)
        out.extend(struct.pack('>I', len(ihdr_data)))
        out.extend(b'IHDR')
        out.extend(ihdr_data)
        out.extend(struct.pack('>I', zlib.crc32(b'IHDR' + ihdr_data) & 0xffffffff))

        # IDAT
        out.extend(struct.pack('>I', len(compressed)))
        out.extend(b'IDAT')
        out.extend(compressed)
        out.extend(struct.pack('>I', zlib.crc32(b'IDAT' + compressed) & 0xffffffff))

        # IEND
        out.extend(struct.pack('>I', 0))
        out.extend(b'IEND')
        out.extend(struct.pack('>I', zlib.crc32(b'IEND') & 0xffffffff))

        return bytes(out)


def hex_to_rgb(hex_str: str) -> tuple:
    hex_str = hex_str.lstrip('#')
    return tuple(int(hex_str[i:i+2], 16) for i in (0, 2, 4))


def generate_security_card_png(
    title: str,
    subtitle: str,
    badge_text: str,
    badge_type: str,
    sections: dict,
    callout_label: str,
    callout_text: str,
    footer_text: str
) -> bytes:
    """Genera la imagen PNG de la tarjeta de seguridad completa con estilo profesional."""
    color_map = {
        'CRITICAL':  {'header': (183, 28, 28),   'badge_bg': (255, 235, 238), 'badge_text': (183, 28, 28),   'border': (239, 83, 80)},
        'HIGH':      {'header': (230, 81, 0),    'badge_bg': (255, 243, 224), 'badge_text': (230, 81, 0),    'border': (255, 152, 0)},
        'MEDIUM':    {'header': (245, 127, 23),  'badge_bg': (255, 253, 231), 'badge_text': (245, 127, 23),  'border': (255, 238, 88)},
        'LOW':       {'header': (2, 119, 189),   'badge_bg': (225, 245, 254), 'badge_text': (2, 119, 189),   'border': (41, 182, 246)},
        'BLOCKED':   {'header': (183, 28, 28),   'badge_bg': (255, 235, 238), 'badge_text': (183, 28, 28),   'border': (239, 83, 80)},
        'CONTAINED': {'header': (13, 71, 161),   'badge_bg': (227, 242, 253), 'badge_text': (13, 71, 161),   'border': (66, 165, 245)},
    }
    theme = color_map.get(badge_type.upper(), {'header': (30, 41, 59), 'badge_bg': (241, 245, 249), 'badge_text': (30, 41, 59), 'border': (148, 163, 184)})

    width = 760
    # Calcular altura dinámica
    num_rows = sum(len(kvs) for kvs in sections.values())
    num_secs = len(sections)
    height = 140 + (num_secs * 30) + (num_rows * 24) + 120 + 50

    canvas = Canvas(width, height, bg_color=(240, 243, 246))

    card_x = 20
    card_y = 20
    card_w = width - 40
    card_h = height - 40

    # Fondo de la tarjeta (Blanco)
    canvas.fill_rect(card_x, card_y, card_w, card_h, (255, 255, 255))
    canvas.draw_rect(card_x, card_y, card_w, card_h, (226, 232, 240), border_width=2)

    # Cabecera de color
    header_h = 64
    canvas.fill_rect(card_x, card_y, card_w, header_h, theme['header'])
    canvas.draw_text(card_x + 20, card_y + 12, subtitle.upper(), (255, 255, 255), scale=1)
    canvas.draw_text(card_x + 20, card_y + 28, title, (255, 255, 255), scale=2)

    cur_y = card_y + header_h + 16

    # Badge de severidad / acción
    badge_str = f" {badge_text} "
    badge_w = len(badge_str) * 12 + 10
    badge_h = 22
    canvas.fill_rect(card_x + 20, cur_y, badge_w, badge_h, theme['badge_bg'])
    canvas.draw_rect(card_x + 20, cur_y, badge_w, badge_h, theme['border'], border_width=1)
    canvas.draw_text(card_x + 26, cur_y + 4, badge_str, theme['badge_text'], scale=2)

    cur_y += badge_h + 16

    # Secciones
    for sec_title, kvs in sections.items():
        # Título de sección
        canvas.draw_text(card_x + 20, cur_y, sec_title, (51, 65, 85), scale=2)
        cur_y += 18
        canvas.fill_rect(card_x + 20, cur_y, card_w - 40, 2, (226, 232, 240))
        cur_y += 8

        # Filas clave-valor
        for k, v in kvs:
            # Clave
            canvas.draw_text(card_x + 24, cur_y, str(k), (100, 116, 139), scale=2)
            # Valor (monoespaciado oscuro)
            val_str = str(v)
            if len(val_str) > 40:
                val_str = val_str[:37] + "..."
            canvas.draw_text(card_x + 240, cur_y, val_str, (15, 23, 42), scale=2)
            cur_y += 22
        cur_y += 10

    # Bloque de Diagnóstico / Detalle
    if callout_text:
        canvas.draw_text(card_x + 20, cur_y, callout_label, (51, 65, 85), scale=2)
        cur_y += 18
        canvas.fill_rect(card_x + 20, cur_y, card_w - 40, 2, (226, 232, 240))
        cur_y += 8

        callout_box_h = 52
        canvas.fill_rect(card_x + 20, cur_y, card_w - 40, callout_box_h, (248, 250, 252))
        canvas.fill_rect(card_x + 20, cur_y, 6, callout_box_h, theme['border'])
        canvas.draw_rect(card_x + 20, cur_y, card_w - 40, callout_box_h, (226, 232, 240), border_width=1)

        canvas.draw_text_wrapped(card_x + 36, cur_y + 10, callout_text, card_w - 70, (30, 41, 59), scale=1)
        cur_y += callout_box_h + 16

    # Pie de página
    footer_h = 32
    footer_y = card_y + card_h - footer_h
    canvas.fill_rect(card_x, footer_y, card_w, footer_h, (241, 245, 249))
    canvas.draw_rect(card_x, footer_y, card_w, footer_h, (226, 232, 240), border_width=1)
    canvas.draw_text(card_x + 140, footer_y + 10, footer_text, (100, 116, 139), scale=1)

    return canvas.to_png_bytes()
