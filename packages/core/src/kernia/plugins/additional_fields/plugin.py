"""Plugin that declares + persists user-defined extra fields on core tables."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any

from kernia.error import APIError
from kernia.types.adapter import FieldDef, Where
from kernia.types.context import EndpointContext
from kernia.types.endpoint import AuthEndpoint
from kernia.types.hooks import AfterHook, PluginHooks
from kernia.types.plugin import KerniaPlugin, PluginSchema

AdditionalFieldsConfig = Mapping[str, Mapping[str, Mapping[str, Any]]]
# Shape: { "<modelName>": { "<fieldName>": {"type": "string", "required": True, ...} } }


_SUPPORTED_TYPES: set[str] = {
    "string",
    "number",
    "boolean",
    "date",
    "json",
    "uuid",
    "text",
    "string[]",
    "number[]",
}


def _to_field_defs(spec: Mapping[str, Mapping[str, Any]]) -> tuple[FieldDef, ...]:
    out: list[FieldDef] = []
    for name, attrs in spec.items():
        ty = attrs.get("type", "string")
        if ty not in _SUPPORTED_TYPES:
            raise ValueError(f"Unsupported additional field type {ty!r} for {name!r}")
        out.append(
            FieldDef(
                name=name,
                type=ty,
                required=bool(attrs.get("required", False)),
                unique=bool(attrs.get("unique", False)),
                default=attrs.get("default"),
            )
        )
    return tuple(out)


_SIGN_UP_PATHS = {"/sign-up/email", "/sign-up/username", "/sign-in/anonymous"}


@dataclass(frozen=True)
class _AdditionalFieldsPlugin:
    id: str = "additional-fields"
    version: str | None = "0.0.0"
    schema: PluginSchema | None = None
    endpoints: tuple[AuthEndpoint, ...] = ()
    middlewares: None = None
    hooks: PluginHooks | None = None
    on_request: None = None
    on_response: None = None
    rate_limit: None = None
    error_codes: Mapping[str, str] = field(default_factory=dict)
    init: None = None


def additional_fields(config: AdditionalFieldsConfig) -> KerniaPlugin:
    """Construct the additional_fields plugin.

    Required-field validation happens in the after-hook scoped to sign-up
    routes (the core route doesn't know about the extra fields, so the body
    arrives without them — we pull from `request.json()` manually).
    """
    extend: dict[str, list[FieldDef]] = {}
    for model_name, fields_spec in config.items():
        extend[model_name] = list(_to_field_defs(fields_spec))

    user_spec = dict(config.get("user", {}))

    async def after_signup(ctx: EndpointContext, result: object) -> object | None:
        if ctx.request.path not in _SIGN_UP_PATHS:
            return None
        if not isinstance(result, dict):
            return None
        user = result.get("user")
        if not isinstance(user, dict) or not user.get("id"):
            return None
        raw = await ctx.request.json()
        if not isinstance(raw, dict):
            return None

        updates: dict[str, Any] = {}
        for name, attrs in user_spec.items():
            value = raw.get(name)
            if value is None:
                if attrs.get("required"):
                    raise APIError(
                        400,
                        "INVALID_REQUEST",
                        message=f"Required additional field {name!r} is missing.",
                    )
                if "default" in attrs:
                    updates[name] = attrs["default"]
                continue
            updates[name] = value

        if not updates:
            return None

        updated = await ctx.auth.adapter.update(
            model="user",
            where=(Where(field="id", value=user["id"]),),
            update=updates,
        )
        if updated is not None:
            result["user"] = updated
        return result

    hooks = PluginHooks(
        after=(
            AfterHook(match=lambda ctx: ctx.request.path in _SIGN_UP_PATHS, handler=after_signup),
        )
    )

    return _AdditionalFieldsPlugin(  # type: ignore[return-value]
        schema=PluginSchema(extend={k: tuple(v) for k, v in extend.items()}),
        hooks=hooks,
    )
