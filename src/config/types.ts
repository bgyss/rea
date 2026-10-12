import type { LogLevel } from "../logger.js";
import type { ReferenceSourcePolicy } from "../domain/referenceSourcePolicy.js";
import type { AnalysisProviderSelector } from "../contracts/providerSelection.js";

import type { GhidraLanguageOverride } from "./ghidraLanguageOverride.js";
import type { GhidraLoaderExtensionConfig } from "./ghidraLoaderExtensions.js";
import type { McpInputSchemaProfile } from "./mcpInputSchemaProfile.js";

export interface AppConfig {
  readonly mcpMaxResponseBytes?: number;
  readonly mcpInputSchemaProfile?: McpInputSchemaProfile;
  readonly analysisProvider: AnalysisProviderSelector;
  readonly idaMcpConfigPath?: string;
  readonly ghidraInstallDir: string | undefined;
  readonly ghidraJavaHome: string | undefined;
  readonly ghidraStartupTimeoutMs: number;
  readonly ghidraLanguageOverride?: GhidraLanguageOverride;
  readonly ghidraDisabledAnalyzers?: readonly string[];
  readonly ghidraSeedFile?: string;
  readonly ghidraNativeAotJar?: string;
  /** Operator-pinned Ghidra loader jars, installed per session when a target needs them. */
  readonly ghidraLoaderExtensions?: readonly GhidraLoaderExtensionConfig[];
  /** Private root for persistent analysed Ghidra projects; absent keeps imports ephemeral. */
  readonly ghidraProjectCacheDir?: string;
  readonly ilspyCmdPath: string | undefined;
  readonly hopperLauncherPath: string;
  readonly hopperStartupTimeoutMs: number;
  readonly hopperTargetPath: string | undefined;
  readonly hopperTargetKind: "executable" | "database";
  readonly hopperLoaderArgs: readonly string[];
  readonly logLevel: LogLevel;
  readonly referenceSourcePolicy: ReferenceSourcePolicy;
}
