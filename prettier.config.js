/** @type {import('prettier').Config} */
const config = {
  semi: true,
  useTabs: false,
  singleQuote: true,
  trailingComma: 'es5',
  printWidth: 100,
  plugins: ['@trivago/prettier-plugin-sort-imports'],
  importOrderSeparation: true,
  importOrderSortSpecifiers: true,
};

export default config;
