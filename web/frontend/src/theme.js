export const palette = {
  bg:           '#05070B',
  surface:      '#0A1020',
  border:       '#1D2A3A',
  primary:      '#19C8FF',
  primaryHover: '#54D9FF',
  secondary:    '#FF5A1F',
  secondaryHov: '#FF7A3C',
  text:         '#E6F3FF',
  muted:        '#8EA3B8',
  danger:       '#FF4D4D',
  success:      '#27D980',
  amber:        '#FFB84D',
}

export const riskColor = (v) =>
  v >= 50 ? palette.danger :
  v >= 20 ? palette.secondary :
  v >= 5  ? palette.amber :
             palette.success

export const darkPlot = {
  paper_bgcolor: 'transparent',
  plot_bgcolor:  'transparent',
  font: { color: palette.text, size: 11 },
}

export const antdTheme = {
  colorPrimary:         palette.primary,
  colorError:           palette.danger,
  colorSuccess:         palette.success,
  colorWarning:         palette.secondary,
  colorBgBase:          palette.bg,
  colorBgContainer:     palette.surface,
  colorBgElevated:      '#0D1928',
  colorBgLayout:        palette.bg,
  colorBorder:          palette.border,
  colorBorderSecondary: palette.border,
  colorText:            palette.text,
  colorTextSecondary:   palette.muted,
  colorTextTertiary:    palette.muted,
  colorTextQuaternary:  '#4A5E72',
  borderRadius:         6,
}

export const antdComponents = {
  Layout: {
    siderBg:  palette.surface,
    headerBg: palette.bg,
    bodyBg:   palette.bg,
    footerBg: palette.bg,
  },
  Menu: {
    darkItemBg:            palette.surface,
    darkSubMenuItemBg:     palette.bg,
    darkItemSelectedBg:    'rgba(25, 200, 255, 0.15)',
    darkItemSelectedColor: palette.primary,
    darkItemColor:         palette.muted,
    darkItemHoverColor:    palette.text,
    darkItemHoverBg:       'rgba(25, 200, 255, 0.08)',
  },
}
