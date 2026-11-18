/** Shared contracts for checked JavaScript. Keep these aligned with IR v2. */
export type AccessPathSegment = string | number;
export type ParameterRole = 'request' | 'body' | 'query' | 'path' | 'header' | 'response' | 'context' | 'continuation' | 'service' | 'logger' | 'database' | 'cancellation' | 'error' | 'capture' | 'unknown';
export type ParameterKind = 'positional-only' | 'positional-or-keyword' | 'keyword-only' | 'variadic-positional' | 'variadic-keyword' | 'variadic';
export type ArgumentKind = 'positional' | 'named' | 'unpack' | 'unpack-positional' | 'unpack-keyword' | 'unknown';
export interface CallBinding {
  kind: ParameterKind;
  hasDefault?: boolean;
  defaultExpression?: string;
  defaultConstant?: boolean;
  defaultTruncated?: boolean;
  defaultLine?: number;
}
export interface CallableParameter {
  name: string;
  type: string;
  optional?: boolean;
  variadic?: boolean;
  raw?: string;
  callBinding?: CallBinding;
}
/** Structural AST view used by language adapters, independent of parser runtime globals. */
export interface SyntaxNode {
  type: string;
  text: string;
  hasError: boolean;
  startIndex: number;
  endIndex: number;
  startPosition: { row: number; column: number };
  parent: SyntaxNode | null;
  children: SyntaxNode[];
  namedChildren: SyntaxNode[];
  childForFieldName(name: string): SyntaxNode | null;
}
export interface SyntaxFunctionRecord {
  node: SyntaxNode;
  enclosingScope: string;
  parameterDescriptors: CallableParameter[];
}
export type AccessorSummary =
  | { kind: 'read'; path: AccessPathSegment[]; constant?: false }
  | { kind: 'read'; constant: true; path?: never }
  | { kind: 'write'; path: AccessPathSegment[]; parameterIndex: number; returnsReceiver: boolean };
export interface SymbolMetadata {
  parameterIndex?: number;
  bindings?: { name: string; path: AccessPathSegment[] }[];
  captured?: boolean;
  annotations?: string[];
  cascadedValidation?: boolean;
  callBinding?: CallBinding;
}
export interface SymbolValue extends SymbolMetadata {
  kind: 'symbol';
  name: string;
  type: string;
  role?: ParameterRole;
}
export interface SourceLocation {
  absolutePath: string;
  relativePath: string;
  line: number;
  endLine: number;
  code: string;
  startColumn?: number;
  endColumn?: number;
  startOffset?: number;
  endOffset?: number;
}
export interface GuardScope {
  applicableSinkKinds: string[];
  outputScoped: boolean;
  receiverScoped: boolean;
  requiresTrustedOperand: boolean;
  requiresSemanticProof?: boolean;
  forbidsDirectSinkInput?: boolean;
}
export interface GuardBinding extends GuardScope {
  capabilities: string[];
  inputs: string[];
  output?: string;
  receiver?: string;
  trustedOperands?: { index: number; expression: string; value: unknown }[];
  protectedOutputs?: string[];
  semanticVerification?: string;
  capabilityScopes?: Record<string, GuardScope>;
  valueVersions?: Record<string, number>;
  collectionFacts?: unknown;
}
export interface CallArguments {
  receiver?: string;
  arguments?: string[];
  argumentKinds?: ArgumentKind[];
  argumentNames?: string[];
  argumentValues?: string[];
  argumentVariables?: string[][];
  argumentConstantFlags?: boolean[];
  accessorArgumentPaths?: string[];
}
export interface Call extends CallArguments {
  function: string;
  expression?: string;
  targetFunctionId?: string;
  closure?: boolean;
  argumentInputs?: SymbolValue[][];
  receiverInputs?: SymbolValue[];
  argumentTypes?: string[];
  argumentRanges?: { startOffset?: number; endOffset?: number }[];
  symbol?: { receiverType?: string; [key: string]: unknown };
}
export interface Operation {
  id: string;
  kind: 'source' | 'assignment' | 'call' | 'return' | 'throw' | 'break' | 'continue' | 'branch' | 'guard' | 'sink';
  functionId: string;
  location: SourceLocation;
  inputs: SymbolValue[];
  output?: SymbolValue;
  semantic: { label?: string; category?: string; sourceKind?: string; exposure?: string; sinkKind?: string; guardCapabilities?: string[]; modelId?: string; modelRole?: string };
  certainty: 'high' | 'medium' | 'low';
  call?: Call;
  metadata: { guardBinding?: GuardBinding; [key: string]: unknown };
}
export interface FunctionIR {
  id: string;
  symbolKey: string;
  name: string;
  language: string;
  enclosingScope: string;
  packageName?: string;
  namespaceName?: string;
  qualifiedEnclosingScope: string;
  implementedTypes: string[];
  declarationKind: string;
  executable: boolean;
  accessorSummary?: AccessorSummary;
  signature: string;
  location: SourceLocation;
  parameters: SymbolValue[];
  operations: Operation[];
  cfg?: unknown;
  references: unknown[];
  entryPoint?: unknown;
  entryPoints: unknown[];
  isGlobal: boolean;
}
export interface FileIR {
  schema: 'traceguard-ir';
  version: number;
  language: string;
  absolutePath: string;
  relativePath: string;
  lines: number;
  frontend: { id: string; mode: string; capability: string };
  functions: FunctionIR[];
  entryPoints: unknown[];
  typeRelations: unknown[];
}
/** The signature subset consumed by the argument binder, after IR adaptation. */
export interface BindingFunction {
  language: string;
  parameters: string[];
  parameterDetails?: { callBinding?: CallBinding }[];
}
export type ArgumentBinding =
  | { kind: 'explicit'; parameterIndex: number; argumentIndex: number; parameterPath: AccessPathSegment[]; uncertain?: boolean }
  | { kind: 'default'; parameterIndex: number; parameterPath: AccessPathSegment[]; argumentIndex?: never; uncertain?: never };
export interface BindingResult {
  status: 'verified' | 'unresolved' | 'invalid';
  valid: boolean;
  strict: boolean;
  special: boolean;
  bindings: ArgumentBinding[];
  reason: string;
}
