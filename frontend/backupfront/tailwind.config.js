/** @type {import('tailwindcss').Config} */
module.exports = {
  content: ["./*.{html,js}"],
  theme: {
    extend: {
      spacing: {
        '35': '8.75rem',
        '30': '7.5rem',
        '15': '3.75rem',
        '7.5': '1.875rem',
      },
      borderRadius: {
        '20': '1.25rem',
      }
    },
    colors: {
      transparent: 'transparent',
      'primary': '#04B2B2',
      'black': '#151515',
      'feature': '#212E37',
      'features': '#504CFE',
      'secondary': '#67696E',
      'placehover': '#B1B1B1',
      'line': '#E4E4E4',
      'surface': '#F5F7F9',
      'white': '#fff',
      'red': '#EB4D4D',
      'success': '#37B853',
      'yellow': '#F4AA1A',
      'background': '#eef7f7',
      'light': 'rgba(255, 255, 255, 0.1)',
      'linear-primary': 'rgba(16, 153, 153, 0.1)',
    },
  },
  plugins: [],
}