"""Рисует иконку приложения: тёмный скруглённый квадрат, телефон, шкала сигнала, зелёная галочка.

    python stand/ui/assets/make_icon.py   → icon.ico + icon.png рядом
"""
import os

from PIL import Image, ImageDraw

HERE = os.path.dirname(os.path.abspath(__file__))
BG_TOP, BG_BOTTOM = (22, 29, 38), (12, 17, 24)
BORDER = (59, 130, 246)
PHONE = (230, 237, 243)
SCREEN = (14, 19, 25)
GREEN = (34, 197, 94)
AMBER = (245, 158, 11)


def render(size):
    scale = 8
    big = size * scale
    img = Image.new("RGBA", (big, big), (0, 0, 0, 0))
    draw = ImageDraw.Draw(img)
    radius = big * 0.22
    grad = Image.new("RGBA", (big, big))
    gdraw = ImageDraw.Draw(grad)
    for y in range(big):
        t = y / big
        color = tuple(int(BG_TOP[i] * (1 - t) + BG_BOTTOM[i] * t) for i in range(3)) + (255,)
        gdraw.line([(0, y), (big, y)], fill=color)
    mask = Image.new("L", (big, big), 0)
    ImageDraw.Draw(mask).rounded_rectangle([0, 0, big - 1, big - 1], radius=radius, fill=255)
    img.paste(grad, (0, 0), mask)
    draw.rounded_rectangle([0, 0, big - 1, big - 1], radius=radius, outline=BORDER + (255,),
                           width=max(1, big // 40))

    pw, ph = big * 0.36, big * 0.62
    px, py = big * 0.16, big * 0.19
    draw.rounded_rectangle([px, py, px + pw, py + ph], radius=big * 0.07, fill=PHONE + (255,))
    inset = big * 0.035
    draw.rounded_rectangle([px + inset, py + inset * 1.6, px + pw - inset, py + ph - inset * 2.2],
                           radius=big * 0.035, fill=SCREEN + (255,))
    draw.ellipse([px + pw / 2 - big * 0.02, py + ph - inset * 1.7, px + pw / 2 + big * 0.02, py + ph - inset * 0.5],
                 fill=SCREEN + (255,))
    draw.line([(px + pw / 2, py + ph), (px + pw / 2, big * 0.93)], fill=PHONE + (255,), width=max(2, big // 30))

    bars = 4
    bx = big * 0.60
    bw = big * 0.065
    gap = big * 0.03
    for i in range(bars):
        h = big * (0.12 + 0.11 * i)
        x0 = bx + i * (bw + gap)
        y1 = big * 0.62
        color = GREEN if i < 3 else AMBER
        draw.rounded_rectangle([x0, y1 - h, x0 + bw, y1], radius=bw / 3, fill=color + (255,))

    cx, cy = px + pw / 2, py + ph * 0.45
    r = pw * 0.30
    draw.ellipse([cx - r, cy - r, cx + r, cy + r], fill=GREEN + (255,))
    w = max(2, int(big * 0.03))
    draw.line([(cx - r * 0.45, cy), (cx - r * 0.1, cy + r * 0.38), (cx + r * 0.5, cy - r * 0.38)],
              fill=(255, 255, 255, 255), width=w, joint="curve")
    return img.resize((size, size), Image.LANCZOS)


def main():
    sizes = [256, 128, 64, 48, 32, 24, 16]
    frames = [render(s) for s in sizes]
    frames[0].save(os.path.join(HERE, "icon.png"))
    frames[0].save(os.path.join(HERE, "icon.ico"), format="ICO", sizes=[(s, s) for s in sizes],
                   append_images=frames[1:])
    print("icon.ico + icon.png готовы")


if __name__ == "__main__":
    main()
