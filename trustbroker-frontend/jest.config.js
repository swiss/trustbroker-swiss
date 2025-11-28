module.exports = {
	preset: 'jest-preset-angular',
	setupFilesAfterEnv: ['<rootDir>/setup-jest.ts'],
	transformIgnorePatterns: [
		'node_modules/(?!(@angular/common/locales/.*|.*\\.mjs$|.*\\.mts$|.*\\.ts$))'
	],
};
