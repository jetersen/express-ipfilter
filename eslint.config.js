const eslint = require('@eslint/js')
const prettier = require('eslint-config-prettier')
const jestPlugin = require('eslint-plugin-jest')
const prettierPlugin = require('eslint-plugin-prettier')

module.exports = [
  {
    ignores: ['coverage/**'],
  },
  eslint.configs.recommended,
  {
    files: ['**/*.js'],
    languageOptions: {
      ecmaVersion: 2018,
      sourceType: 'script',
      globals: {
        require: 'readonly',
        module: 'readonly',
        exports: 'readonly',
        __dirname: 'readonly',
        __filename: 'readonly',
        process: 'readonly',
        console: 'readonly',
        Buffer: 'readonly',
        setTimeout: 'readonly',
        clearTimeout: 'readonly',
        setInterval: 'readonly',
        clearInterval: 'readonly',
      },
    },
    plugins: {
      prettier: prettierPlugin,
      jest: jestPlugin,
    },
    rules: {
      'prettier/prettier': 'warn',
      'no-console': 'off',
      'no-unused-vars': 'warn',
      'no-var': 'warn',
      'no-use-before-define': 'warn',
      'prefer-arrow-callback': 'warn',
    },
  },
  {
    files: ['test/**/*.js'],
    languageOptions: {
      globals: {
        ...require('globals').jest,
      },
    },
    plugins: {
      jest: jestPlugin,
    },
    rules: {
      ...jestPlugin.configs['flat/recommended'].rules,
      'jest/no-done-callback': 'off',
      'jest/expect-expect': 'off',
    },
  },
  prettier,
]
