import { test } from 'node:test';
import assert from 'node:assert/strict';

// Negative control for CI, not a property of the boundary.
//
// verify.yml pipes `npm test` into `tee`. Without pipefail the step's exit code is tee's,
// so a failing suite still reported green. The workflow now runs this file with
// CI_NEGATIVE_CONTROL=1 through the same pipe and asserts the step sees a non-zero exit.
// Unset (every normal run), the test passes and asserts nothing about the system.
test('CI negative control: fails if and only if CI_NEGATIVE_CONTROL=1', () => {
  assert.notEqual(
    process.env.CI_NEGATIVE_CONTROL,
    '1',
    'deliberate failure: CI_NEGATIVE_CONTROL=1 (this run must exit non-zero)',
  );
});
