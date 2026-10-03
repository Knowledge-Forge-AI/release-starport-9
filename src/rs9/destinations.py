"""Operator routing subset; validation grants no publication authority."""
from urllib.parse import urlsplit
from rs9.constants import ADAPTER_NAMES, SCHEMA_DESTINATIONS, VALID_DESTINATION_STATUSES, VALID_MODES
from rs9.errors import ContractError
from rs9.fields import choice, platforms, read_toml, schema, table, typed, unique_rows
from rs9.security import validate_repository, validate_slug


def validate_url(value):
    url = typed(value, str, "destination URL")
    if any(c.isspace() or ord(c) < 32 or c == "\\" for c in url):
        raise ContractError("INVALID_URL", "Invalid characters in destination URL")
    try:
        parsed = urlsplit(url)
        parsed.port
    except ValueError:
        raise ContractError("INVALID_URL", "Invalid destination URL") from None
    if parsed.scheme != "https" or not parsed.hostname or "@" in parsed.netloc:
        raise ContractError("INVALID_URL", "Destination requires HTTPS without userinfo")
    if parsed.query or parsed.fragment:
        raise ContractError("INVALID_URL", "Destination query/fragment is forbidden")


def validate_destination(value):
    dest = table(value, {"id", "adapter", "mode", "platforms", "status", "base-url", "repository", "profile"}, "destination",
                 required={"id", "adapter", "mode", "platforms", "status"})
    validate_slug(dest.get("id"), "destination.id")
    choice(dest.get("adapter"), ADAPTER_NAMES, "destination.adapter")
    choice(dest.get("mode"), VALID_MODES, "destination.mode")
    platforms(dest.get("platforms"), False)
    choice(dest.get("status"), VALID_DESTINATION_STATUSES, "destination.status")
    if "base-url" in dest:
        validate_url(dest["base-url"])
    if "repository" in dest:
        validate_repository(dest["repository"])
    if "profile" in dest:
        choice(dest["profile"], {"aur"}, "destination.profile")
        if dest["adapter"] != "pacman" or dest["mode"] != "projection":
            raise ContractError("INVALID_CONFIG", "Destination profile 'aur' is only permitted for pacman projection destinations")



def load_destinations(path, *, input_hashes=None):
    doc, digest = read_toml(path)
    table(doc, {"schema", "destinations"}, "destinations file", required={"schema", "destinations"})
    schema(doc, SCHEMA_DESTINATIONS)
    destinations = typed(doc.get("destinations"), list, "destinations")
    if not destinations:
        raise ContractError("INVALID_CONFIG", "Destinations cannot be empty")
    for destination in destinations:
        validate_destination(destination)
    unique_rows(destinations, "id")
    if input_hashes is not None:
        input_hashes["destinations.toml"] = digest
    return doc
