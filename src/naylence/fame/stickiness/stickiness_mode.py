from enum import Enum


class StickinessMode(str, Enum):
    STRICT = "strict"
    SIGNED_OPTIONAL = "signed-optional"
    SID_ONLY = "sid-only"
