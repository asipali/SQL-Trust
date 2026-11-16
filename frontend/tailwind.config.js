/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  theme: {
    extend: {
      colors: {
        brand: {
          DEFAULT: '#176B70',
          50: '#F0F8F8',
          100: '#DBEEF0',
          200: '#B7DEDE',
          300: '#89C8CB',
          400: '#62C6CB',
          500: '#176B70',
          600: '#10565D',
          700: '#0D444A',
          800: '#0A3337',
          900: '#062124',
        },
        teal: {
          DEFAULT: '#176B70',
          deep: '#10565D',
          soft: '#B7DEDE',
          50: '#F0F8F8',
          100: '#DBEEF0',
          200: '#B7DEDE',
          300: '#89C8CB',
          400: '#62C6CB',
          500: '#176B70',
          600: '#10565D',
          700: '#0D444A',
        },
        cyan: {
          DEFAULT: '#62C6CB',
          metallic: '#62C6CB',
          soft: '#B7DEDE',
        },
        navy: {
          DEFAULT: '#142438',
          950: '#0B131E',
          900: '#101C2C', // Dark visualization surface
          800: '#142438', // Deep navy
          700: '#20364B', // Secondary navy
          600: '#2E4D68',
          500: '#3D6282',
        },
        canvas: '#F4F6F8',
        platinum: '#E7ECEF',
        surface: {
          DEFAULT: '#FFFFFF',
          subtle: '#F7F9FA',
          hover: '#F0F4F6',
          viz: '#101C2C',
        },
        appBorder: {
          DEFAULT: '#DCE3E8',
          subtle: '#EAEFF2',
          dark: '#1F344A',
        },
        appText: {
          primary: '#182532',
          secondary: '#647482',
          muted: '#8B9DAA',
          inverse: '#FFFFFF',
          cyan: '#62C6CB',
        },
        status: {
          success: '#23836B',
          'success-bg': '#ECF8F4',
          'success-border': '#B3E4D6',
          warning: '#B98235',
          'warning-bg': '#FFFBF0',
          'warning-border': '#FDE2B5',
          critical: '#C34E55',
          'critical-bg': '#FEF2F2',
          'critical-border': '#F8C2C5',
        }
      },
      fontFamily: {
        sans: [
          'Inter',
          '-apple-system',
          'BlinkMacSystemFont',
          'Segoe UI',
          'Roboto',
          'Helvetica Neue',
          'sans-serif'
        ],
        mono: [
          'JetBrains Mono',
          'Fira Code',
          'ui-monospace',
          'SFMono-Regular',
          'Menlo',
          'Monaco',
          'Consolas',
          'monospace'
        ]
      },
      boxShadow: {
        'xs': '0 1px 2px 0 rgba(16, 28, 44, 0.04)',
        'card': '0 1px 3px 0 rgba(16, 28, 44, 0.05), 0 1px 2px -1px rgba(16, 28, 44, 0.04)',
        'card-hover': '0 4px 10px -2px rgba(16, 28, 44, 0.08), 0 2px 6px -2px rgba(16, 28, 44, 0.04)',
        'modal': '0 20px 25px -5px rgba(16, 28, 44, 0.12), 0 8px 10px -6px rgba(16, 28, 44, 0.06)',
        'viz': '0 8px 24px -4px rgba(16, 28, 44, 0.35)',
      }
    },
  },
  plugins: [],
}
