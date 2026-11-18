import { functionIR, symbol, operation } from '../../src/ir/schema';
import { bindCallArguments } from '../../src/dataflow/call-bindings';
import type { CallBinding, AccessorSummary, GuardBinding } from '../../src/ir/contracts';

const signature: CallBinding = { kind: 'keyword-only', hasDefault: true };
symbol('command', 'string', 'body', { callBinding: signature });
// @ts-expect-error Array.map also passes index and array, which are not type and role.
['command'].map(symbol);
// @ts-expect-error Misspelled signature fields must not silently become undefined.
symbol('command', 'string', 'body', { callBindings: signature });
// @ts-expect-error Parameter kind is a closed set.
const wrongKind: CallBinding = { kind: 'named' };
// @ts-expect-error A getter must declare a field or a constant result.
const incompleteGetter: AccessorSummary = { kind: 'read' };
// @ts-expect-error A setter needs its argument index.
const incompleteSetter: AccessorSummary = { kind: 'write', path: ['value'], returnsReceiver: false };
declare const guard: GuardBinding;
// @ts-expect-error Guard field typos must be rejected.
guard.protectedOutput;
const location = { absolutePath: '/repo/test.py', relativePath: 'test.py', line: 1, endLine: 1, code: 'value' };
const operationInput = { id: 'operation', functionId: 'function', location };
operation({ ...operationInput, kind: 'assignment' });
// @ts-expect-error Operation kinds are validated statically at checked boundaries.
operation({ ...operationInput, kind: 'assingment' });
const functionInput = { id: 'function', name: 'run', language: 'python', location };
functionIR({ ...functionInput, accessorSummary: { kind: 'read', path: ['value'] } });
// @ts-expect-error Function accessors cannot use an invented kind.
functionIR({ ...functionInput, accessorSummary: { kind: 'getter', path: ['value'] } });
const result = bindCallArguments({ language: 'python', parameters: ['value'], parameterDetails: [{ callBinding: signature }] }, { arguments: ['input'], argumentKinds: ['named'], argumentNames: ['value'] });
for (const binding of result.bindings) {
  if (binding.kind === 'explicit') binding.argumentIndex.toFixed();
  // @ts-expect-error Bindings expose argumentIndex rather than an untyped index.
  binding.argIndex;
}
