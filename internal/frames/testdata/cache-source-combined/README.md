# Shared scheduler and cache declaration

This synthetic fixture has both journal capabilities enabled, as a WBFT node
does. One raw segment record supplies one R01 row with both declarations.
The row keeps its original sequence and position; no second sequence is
invented. The remaining operations and delayed write match the cache-only
fixture. It is a finite metadata test, without a full signed consensus chain
or authentication of unavailable raw source bytes.
