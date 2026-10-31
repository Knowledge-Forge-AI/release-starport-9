"""Explicit simulated native-domain seam for historical synthetic 071 fixtures.

These fixtures exercise the pre-existing owner/consumer machinery with tiny
synthetic archives. They cannot authenticate the real published native assets.
New product-native tests exercise the real replay independently.
"""
from unittest import mock
from rs9 import nebular071_product_native as native
from rs9 import nebular071_universal_consumer as consumer


def install_simulated_native_domain(case):
    def simulated_frame(capture, ref=None, asset=None):
        if ref is not None:
            native.validate_reference(ref)
        frame = consumer.authenticated_product_release(capture)
        return {"schema": "rs9.nebular071-product-native-admission-frame.v1",
                "reference": native.reference(), "product_source": frame["source"],
                "assets": [], "compiler_relation": "simulated-fixture-only"}
    replay = mock.patch.object(native, "replay_descriptor_native", side_effect=lambda descriptor, root, capture, **kw: object())
    require = mock.patch.object(native, "require_native_admission", side_effect=lambda admission, capture, ref, asset=None: simulated_frame(capture, ref, asset))
    for patch in (replay, require):
        patch.start()
        case.addCleanup(patch.stop)
