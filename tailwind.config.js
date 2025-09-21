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
          600: '#2c4bc7',
          700: '#1e3aa3',
          800: '#13264E', // 메인 브랜드 색상
          900: '#0f1d3a',
          950: '#0a1427',
        },
      },
    },
  },
  plugins: [],
}