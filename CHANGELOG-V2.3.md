# V2.3 — Dark Dashboard Theme

## UI updates
- Added a dark-first dashboard theme with a compact light/dark mode toggle.
- Updated page background, panels, form controls, tables, correlation results, and responsive layout styling.
- Kept existing CTI workflows and API behaviour unchanged.

## Validation
- Backend automated tests remain the same as V2.2.
- The React production build was not run in this packaging environment because dashboard dependencies were not installed here. Run `npm install` and `npm run build` in `cti-dashboard` on the development machine.
