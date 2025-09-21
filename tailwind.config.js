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
          50: '#f1f5ff',
          100: '#e2ebff',
          200: '#c8d5ff',
          300: '#a1b5ff',
          400: '#7688ff',
          500: '#4d5bff',
          600: '#3142f5',
          700: '#2532d8',
          800: '#142755', // 메인 브랜드 색상
          900: '#0f1d42',
          950: '#0a1530',
        },
      },
    },
  },
  plugins: [],
}