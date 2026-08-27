# UI/UX design references

Mockups gathered while redesigning `src/ui`'s visual layer (enrolment face
capture, biometric login moments, home). None of these are followed literally
— citizen-facing branding is still open decision #10, and this is a
government identity app, not a fintech or healthcare product. What's useful
here is the *interaction pattern*, not the brand:

| File | What it shows | What we borrow |
|------|----------------|-----------------|
| `light-teal-onboarding-and-faceid-setup.png` | Calm light theme, soft-rounded auth card, animated dot-tracked face capture with a live percentage, hexagon "Set up Face ID" illustration | The capture screen showing live progress (not a bare spinner), and a calm light palette over a stark white one |
| `dark-face-scan-and-light-fingerprint-login.png` | Full-bleed camera frame with corner brackets + progress bar during capture; a light, quiet fingerprint-unlock screen for returning users | The corner-bracket scan frame as a reusable motif, and the light/dark contrast between "doing something" (capture) and "waiting for you" (unlock) |
| `ipay-dark-neon-face-scan-onboarding.png` | High-contrast dark onboarding, animated radial scan ring during capture, multi-face carousel on completion | The radial progress ring as an alternative to a linear bar, and how a dark capture screen keeps focus on the face against a full-bleed photo |

None of these are on the read-only, org-scoped, WCAG-AA-contrast, or
never-color-alone constraints that `src/ui/theme.ts` and
`CONTRACT.md`/`docs/SPEC.md` 05 §7 already lock in — those constraints win over
anything shown here.
