# Scheduler cancellation boundary

This public synthetic fixture models a retry expiry queued after the next
step entered and before its cancellation request. A later dequeue does not
cancel or alter the queued timeout. It is intentionally a finite prefix,
without a fabricated engine-stop or capture-end event.

The frame rows are exported by wbft-journal from synthetic raw journal
records. Every row keeps its raw sequence and segment/offset. The events
use measured step entry, while operations use their own mutation clocks.
The fixture does not claim to replay a full consensus chain or authenticate
unavailable raw source bytes. Consumer tests also reorder the file, damage
source identities, truncate the snapshot and move the retry queue insertion
after the round arm while keeping a live timer; that last case must fail.
