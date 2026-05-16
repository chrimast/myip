# Admin Custom Provider and Field Plan

## Goal
Allow operators to add/remove custom HTTP JSON providers and custom normalized fields from `/admin`, because different IP intelligence providers expose different raw field names.

## Recommended phased design

### Phase 1: Dynamic metadata only
- Add `custom_providers` and `custom_fields` to `data/admin_provider_config.json`.
- `/api/admin/providers` and `/api/admin/fields` merge built-in definitions with custom definitions.
- Validate IDs and field names, but do not call custom provider HTTP yet.
- UI can add/delete provider/field metadata and define raw-to-normalized mappings.

### Phase 2: Generic JSON HTTP provider runtime
- Implement a safe `GenericJSONLookupProvider`.
- Config shape per provider:
  - `id`
  - `endpoint_url`
  - `method` initially only `GET`
  - `query_param` such as `ip` or templated URL `{ip}`
  - optional `headers` with secret references only, not plaintext values
  - `success_path` / `success_values`
  - `field_map`: normalized field -> list of raw JSON paths
  - `field_transforms`: type coercion such as string/bool/float/asn
- Restrict URL schemes to `https` initially; block localhost/private metadata IPs to avoid SSRF.
- Do not allow arbitrary Python/JS expressions. Use JSON paths and a fixed transform enum.

### Phase 3: UI editor
- Add forms for:
  - add/delete provider
  - add/delete normalized field
  - map provider raw paths to normalized fields
  - test provider against an IP before enabling
- Show a raw response preview and field extraction preview.

### Phase 4: promote to public lookup
- Only custom providers that pass validation and a test lookup can be enabled for `/api/ip`.
- Keep built-in providers available and resettable.

## Field model
A custom normalized field should include:
- `field`: stable snake_case public/internal name
- `label`: display label
- `source_type`: provider_structured, identity_text, registry, derived, custom
- `scoring`: false by default; scoring true only for known structured signals unless a later scoring-weight system is added
- `type`: string, bool, int, float, list, object
- `used_for`: display/debug/compatibility/scoring

## Important constraints
- New custom fields can be displayed and included in admin debug output first, but they should not affect `IPInfo` or `/api/ip` schema until schema strategy is explicit.
- Existing `IPInfo` is a typed Pydantic model; arbitrary new fields need either `extra_fields`/`custom_fields` storage or a dynamic response extension.
- Provider raw field names should be provider-specific mapping entries, not global field names.
- API keys/secrets must be referenced by name and stored separately or in env; never in provider config plaintext.
