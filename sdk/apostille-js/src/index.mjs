// The default and /core entry points are offline-only by construction.
// Network access lives exclusively in the separately imported /client entry.
export * from "./apostille-core.mjs";
export * from "./apostille-erc8004.mjs";
