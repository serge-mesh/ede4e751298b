// Ids derived from names, shown before saving and editable: core derives none for the UI and
// refuses an empty id (422).

/**
 * feeds.md §1's rule for new feed ids, used for every entity id core takes as a slug
 * (1–64 of a-z, 0-9, `-`, `_`): lowercased, characters outside a-z0-9 turned into `-`
 * (one for a run of them), no `-` at either end, at most 64 characters.
 */
export function slugFromName(name: string, max = 64): string {
  let out = "";
  for (const c of name.toLowerCase()) {
    const ok = (c >= "a" && c <= "z") || (c >= "0" && c <= "9");
    if (ok) out += c;
    else if (!out.endsWith("-")) out += "-";
  }
  return out.replace(/^-+/, "").slice(0, max).replace(/-+$/, "");
}

/**
 * A profile id (core.md §2): a DNS label (lowercase letters, digits, hyphens; at most 63; no
 * hyphen at either end) that never ends in `-full`, since that names the full browser list.
 */
export function profileIdFromName(name: string): string {
  let id = slugFromName(name, 63);
  while (id.endsWith("-full")) id = id.slice(0, -"-full".length).replace(/-+$/, "");
  return id;
}

/** The id an entity of this kind would get from its name ("" when the name gives none). */
export function idFromName(kind: string, name: string): string {
  return kind === "profiles" ? profileIdFromName(name) : slugFromName(name);
}

/** core's check for slug ids (config/validate.rs `is_slug`). */
export function isSlug(id: string): boolean {
  return /^[a-z0-9][a-z0-9_-]{0,63}$/.test(id);
}

/** core's check for profile ids (core.md §2). */
export function isProfileId(id: string): boolean {
  return /^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$/.test(id) && !id.endsWith("-full");
}
