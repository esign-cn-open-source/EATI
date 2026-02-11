module.exports = {
    parser: '@typescript-eslint/parser',
    extends: [
        'eslint:recommended'
    ],
    plugins: ['@typescript-eslint'],
    parserOptions: {
        ecmaVersion: 2020,
        sourceType: 'module'
    },
    env: {
        node: true,
        es6: true
    },
    rules: {
        '@typescript-eslint/no-explicit-any': 'warn',
        '@typescript-eslint/no-unused-vars': 'error',
        'no-console': 'off',
        'no-undef': 'off' // TypeScript handles this
    },
    ignorePatterns: ['dist/', 'node_modules/', '*.js']
};