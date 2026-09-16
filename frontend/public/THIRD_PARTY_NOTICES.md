# APEX frontend assets

- APEX wordmark: user-provided artwork. Original PNG retained without pixel changes; the UI clips the surrounding black canvas using CSS.
- UI icons: Astryx `@astryxdesign/core` 0.6.2 `Icon` component and its built-in semantic glyphs. For domain-specific glyphs outside Astryx's registry, `@heroicons/react` 2.2.0 is passed to Astryx Icon through its documented SVG component API. Both MIT; license texts are in `licenses/`.
  - https://astryx.atmeta.com/components/Icon
  - https://github.com/tailwindlabs/heroicons
- File-type icons: original SVG files from Material Icon Theme, MIT. Exact repository commit and selected filenames are recorded in `icons/material/SOURCE.json`; license in `icons/material/LICENSE`.
  - https://github.com/material-extensions/vscode-material-icon-theme/tree/main/icons

All assets are bundled locally. The UI does not fetch icons, fonts, or logo files from a CDN.
