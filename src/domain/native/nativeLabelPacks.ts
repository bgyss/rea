import { z } from "zod";
import { NES_REGISTERS_PACK } from "./labelPacks/nes.js";
import { PS1_REGISTERS_PACK } from "./labelPacks/ps1.js";
import {
  nativeAnnotationSetSchema,
  type LabelPack,
  type NativeAnnotationSet,
} from "./nativeAnnotationSets.js";

/** Built-in label packs, by id. */
export const LABEL_PACKS: Readonly<Record<string, LabelPack>> = Object.freeze({
  [NES_REGISTERS_PACK.id]: NES_REGISTERS_PACK,
  [PS1_REGISTERS_PACK.id]: PS1_REGISTERS_PACK,
});

const packIds = z.enum(Object.keys(LABEL_PACKS) as [string, ...string[]]);

/** Apply one built-in label pack or one inline annotation set. */
export const nativeAnnotationSetInputSchema = z
  .strictObject({
    pack: packIds.optional().describe(
      `Built-in label pack: ${Object.values(LABEL_PACKS)
        .map((pack) => `${pack.id} (${pack.title})`)
        .join("; ")}`,
    ),
    annotations: nativeAnnotationSetSchema
      .optional()
      .describe(
        "Inline annotation set, e.g. the annotations of a rea.label-pack.v1 file",
      ),
  })
  .refine(
    (value) => (value.pack === undefined) !== (value.annotations === undefined),
    "Supply exactly one of pack or annotations",
  );

/** The set a request applies, and the built-in pack it came from. */
export interface ResolvedAnnotationSet {
  readonly annotations: NativeAnnotationSet;
  readonly pack: { readonly id: string; readonly version: number } | null;
}

/** Resolve a validated request to the exact set that is applied and recorded. */
export const resolveAnnotationSet = (
  input: z.infer<typeof nativeAnnotationSetInputSchema>,
): ResolvedAnnotationSet => {
  const pack = input.pack === undefined ? undefined : LABEL_PACKS[input.pack];
  if (pack !== undefined)
    return {
      annotations: pack.annotations,
      pack: { id: pack.id, version: pack.version },
    };
  if (input.annotations === undefined)
    throw new TypeError("A validated annotation set request names no set");
  return { annotations: input.annotations, pack: null };
};
