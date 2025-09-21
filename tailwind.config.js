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
          50: '#f0f6ff',
          100: '#e0ecff',
          200: '#b9d6ff',
          300: '#7bb8ff',
          400: '#3694ff',
          500: '#0a73f1',
          600: '#0052ce',
          700: '#003da6',
          800: '#003876', // 서울대학교 공식 색상
          900: '#002a55',
          950: '#001d3d',
        },
      },
    },
  },
  plugins: [],
}