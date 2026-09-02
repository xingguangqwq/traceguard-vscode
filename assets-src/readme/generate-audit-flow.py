from pathlib import Path

from PIL import Image


WIDTH = 1200
HEIGHT = 750
COLORS = 160

FRAME_FILES = [
    "traceguard-review-queue.png",
    "traceguard-trace-source.png",
    "traceguard-trace-call.png",
    "traceguard-trace-sink.png",
    "traceguard-notes.png",
]

HOLD_MS = [1500, 1100, 1000, 1400, 1900]
BLEND_STEPS = (0.25, 0.5, 0.75)


def fitted_frame(path):
    image = Image.open(path).convert("RGB")
    return image.resize((WIDTH, HEIGHT), Image.Resampling.LANCZOS)


def shared_palette(images):
    strip = Image.new("RGB", (WIDTH, HEIGHT * len(images)))
    for index, image in enumerate(images):
        strip.paste(image, (0, index * HEIGHT))
    return strip.quantize(colors=COLORS, method=Image.Quantize.MEDIANCUT)


def main():
    root = Path(__file__).resolve().parents[2]
    image_dir = root / "docs" / "images"
    sources = [fitted_frame(image_dir / name) for name in FRAME_FILES]
    palette = shared_palette(sources)

    rendered = []
    durations = []
    for index, current in enumerate(sources):
        rendered.append(current.quantize(palette=palette, dither=Image.Dither.NONE))
        durations.append(HOLD_MS[index])
        if index == len(sources) - 1:
            continue
        following = sources[index + 1]
        for amount in BLEND_STEPS:
            transition = Image.blend(current, following, amount)
            rendered.append(transition.quantize(palette=palette, dither=Image.Dither.NONE))
            durations.append(70)

    output = image_dir / "traceguard-audit-flow.gif"
    rendered[0].save(
        output,
        save_all=True,
        append_images=rendered[1:],
        duration=durations,
        loop=0,
        optimize=True,
        disposal=1,
    )
    print(output)


if __name__ == "__main__":
    main()
