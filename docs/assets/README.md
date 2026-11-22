# Brand assets

The mark is a hexagon (a block) with "10" cut out of it: the chain is `b10coin`,
and both glyphs are plain geometry — a flagged stem and a ring, no serifs — so
the cut-out survives down to a 16 px favicon. The gradient runs
`#c7e9ff → #7cc4ff → #3a83d2`, sampled from the site's accent (`--accent:
#7cc4ff`) on its dark background (`#0a0c0f`).

| File | What it is | Where it is used |
| --- | --- | --- |
| `logo-mark.svg` | the mark on its own, transparent | site nav, live-page header, `og` cards |
| `logo.svg` | mark + wordmark lockup (for dark backgrounds) | anywhere a horizontal logo is needed |
| `logo.png` | the lockup rasterised at 2× (544×160, transparent) | README (GitHub does not render SVG through `camo` reliably) |
| `favicon.svg` | 32×32 flat variant: same silhouette, no gradient, thicker glyphs | modern browsers (`rel="icon" type="image/svg+xml"`) |
| `favicon.ico` | 16/32/48 multi-size icon | `/favicon.ico`, the fallback every browser asks for |
| `apple-touch-icon.png` | 180×180, **opaque** (iOS ignores alpha), mark inset 70% so the rounded mask does not clip the hexagon | iOS home screen |
| `icon-192.png`, `icon-512.png` | transparent, for a PWA manifest | if the site ever ships a manifest |
| `og-image.png` | 1200×630 social card | `og:image` / `twitter:image` on both pages |
| `social-preview.png` | 1280×640 | **GitHub → Settings → General → Social preview** (GitHub has no API for this; upload it by hand) |

## Rebuilding the raster files

The SVGs are the source of truth. The PNG/ICO files were produced by rendering
each SVG in Chrome at exactly the target size with a transparent default
background (`Emulation.setDefaultBackgroundColorOverride` with alpha 0 +
`Page.captureScreenshot(omitBackground=true)`), then assembling the `.ico` with
Pillow:

```python
from PIL import Image
Image.open("icon-48.png").convert("RGBA").save("favicon.ico", format="ICO",
                                                sizes=[(16,16),(32,32),(48,48)])
```

`apple-touch-icon.png` is composited on `#0a0c0f` because iOS renders
transparency as black anyway.

Keep the geometry in the three SVGs in sync: the favicon is the mark with a flat
fill and thicker strokes, not a different drawing.
