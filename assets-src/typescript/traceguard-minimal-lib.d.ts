/// <reference no-default-lib="true"/>

interface Object {}
interface Function { readonly name: string; readonly length: number; }
interface CallableFunction extends Function {}
interface NewableFunction extends Function {}
interface IArguments { readonly length: number; [index: number]: any; }
interface String { readonly length: number; toString(): string; }
interface Boolean { valueOf(): boolean; }
interface Number { valueOf(): number; }
interface RegExp {}
interface Array<T> { length: number; [index: number]: T; }
interface ReadonlyArray<T> { readonly length: number; readonly [index: number]: T; }
interface PromiseLike<T> { then<TResult = T>(onfulfilled?: (value: T) => TResult | PromiseLike<TResult>): PromiseLike<TResult>; }
interface Promise<T> extends PromiseLike<T> {}
interface IteratorResult<T> { done?: boolean; value: T; }
interface Iterator<T> { next(...args: [] | [undefined]): IteratorResult<T>; }
interface Iterable<T> { [Symbol.iterator](): Iterator<T>; }
interface SymbolConstructor { readonly iterator: unique symbol; }
declare var Symbol: SymbolConstructor;
interface Map<K, V> { get(key: K): V | undefined; set(key: K, value: V): this; }
interface Set<T> { add(value: T): this; has(value: T): boolean; }
type Record<K extends keyof any, T> = { [P in K]: T };
type Partial<T> = { [P in keyof T]?: T[P] };
type Pick<T, K extends keyof T> = { [P in K]: T[P] };
type Exclude<T, U> = T extends U ? never : T;
type Extract<T, U> = T extends U ? T : never;
type Omit<T, K extends keyof any> = Pick<T, Exclude<keyof T, K>>;
declare const console: { log(...values: any[]): void; error(...values: any[]): void };
