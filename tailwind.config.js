/** @type {import('tailwindcss').Config} */
module.exports = {
  content: ['./public/**/*.{html,js}'],
  theme: {
    extend: {
      fontFamily: {
        sans: ['Inter', 'sans-serif'],
      },
      colors: {
        'navy': {
          50: '#f0f4ff',
          100: '#e0e9ff',
          200: '#c1d1ff',
          300: '#9bb3ff',
          400: '#6b8aff',
          500: '#3b5dff',
          600: '#1a3cdc',
          700: '#0f2bb8',
          800: '#0a1f94', // 메인 브랜드 색상 - 더 어두운 남색
          900: '#061570',
          950: '#040e4d',
        },
      },
    },
  },
  plugins: [],
}