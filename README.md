# MOBIUS — Android AI penetration testing

A static, dependency-free landing page: dark technical-sheet layout, a demo scan console,
capability grid, product mockups, device lab, pricing and FAQ.

**This is a design study, not a product.** The page sells a fictional Android security
platform; every screenshot, metric and finding on it is demo data. It is not affiliated with
djini.ai or any other vendor, and no text from any site was copied.

## Run it

```bash
python3 -m http.server 8000 --bind 0.0.0.0
```

Then open `http://localhost:8000`. Nothing to install, nothing to build.

## Structure

```
index.html          all sections (hero, console, capabilities, inside, devices, terms, pricing, faq)
assets/styles.css   design system: tokens, grid, components, responsive rules
assets/app.js       tab switching, billing toggle, scroll reveal, binary scramble, mobile nav
assets/mark.svg     favicon / logo mark
```

## Notes on the design

- **One accent.** Acid lime for state and action; red/amber/cyan are reserved for severity, so
  colour always means something.
- **Hairlines instead of shadows.** 1px rules and a 72px background grid do the structuring;
  cards get borders, not drop shadows.
- **Numbers, labels, revision stamps.** The blueprint strip, `SHEET 01`, and monospace micro-labels
  are what make it read as an instrument rather than a brochure.
- **Motion with an off switch.** Reveals, the marquee and the console autoplay all respect
  `prefers-reduced-motion`, and the console pauses on hover or focus.
- **Accessibility.** Real `<button>`s with `aria-selected`, arrow-key tab navigation, visible focus
  rings, semantic landmarks, and text contrast checked against the ink background.

## Previous contents

This repository held a Python/Android security-analysis project (MOBIUS). Its full history is
still reachable at commit `d373bba`; the site replaced the working tree on request.
