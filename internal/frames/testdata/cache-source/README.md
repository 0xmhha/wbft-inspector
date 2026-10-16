# Cache decision and delayed write

This public synthetic fixture contains an empty cache declaration, a retry
target decision, a later relay suppression, and the delayed retry write.
The write retains its enqueue attempt and the original cache operation.
Equal cache-operation timestamps do not determine mutex order.

The rows are exported by wbft-journal from synthetic journal records.
Coordinates identify their raw sequence and position; the raw source is not
bundled here. This finite prefix does not claim a complete consensus chain,
authenticated raw bytes, a signed message, or peer delivery.
