"""Protocol decoder registry.

Every decoder subclass decorated with :func:`register` is automatically
available to the sniffing engine.

To add a new protocol:

1. Create ``protocols/my_proto.py``.
2. Subclass :class:`~sniffer.protocols.base.ProtocolDecoder`.
3. Decorate the class with ``@register``.
4. Add an import line at the bottom of this file.
"""

from __future__ import annotations

from typing import Type

from .base import ProtocolDecoder

_registry: list[Type[ProtocolDecoder]] = []


def register(cls: Type[ProtocolDecoder]) -> Type[ProtocolDecoder]:
    """Class decorator -- adds *cls* to the global decoder list."""
    _registry.append(cls)
    return cls


def get_decoders() -> list[ProtocolDecoder]:
    """Return fresh instances of every registered decoder, sorted by priority."""
    return sorted((cls() for cls in _registry), key=lambda d: d.priority)


def get_decoders_for(selection: str) -> list[ProtocolDecoder]:
    """Return decoders filtered by *selection* (a decoder name, or '' / 'Auto-detect' for all)."""
    all_decoders = get_decoders()
    if not selection or selection == "Auto-detect":
        return all_decoders
    filtered = [d for d in all_decoders if d.name == selection]
    return filtered if filtered else all_decoders


# Importing the modules triggers their @register decorators.
from . import bacnet_mstp as _bac  # noqa: E402, F401
from . import n2 as _n2  # noqa: E402, F401
from . import bacnet_ip as _bip  # noqa: E402, F401
from . import ccn as _ccn  # noqa: E402, F401
