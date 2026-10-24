# coldroot

An offline root certificate authority in a box: the software, boot image, and
ceremony procedure for creating and operating the most sensitive keys an
organization owns, built so that others can reproduce and verify it.

## What an offline root is for

Every certificate an organization issues (TLS for internal services, device
and workload identity, VPN and mTLS clients, code signing) ultimately chains
to a root key. Whoever controls that key can impersonate anything in the
organization, and if it is lost, every trust relationship built on it has to
be rebuilt from scratch.

So the root is not used for day-to-day issuance. It signs a small number of
intermediate CAs that run online and do the real work, plus the occasional
revocation list. Then it goes back into storage. Keeping it **offline**,
never on a networked machine, used only during a deliberate, witnessed
**key ceremony**, means a compromise of any online system can be recovered
from by revoking an intermediate, not by starting over.

## Why another approach

Common ways to run an offline root each leave a weak point:

- **A key file on a USB stick or laptop in a safe** is only as trustworthy as
  every machine it has ever touched, and nothing shows whether it was copied.
- **A single HSM in a safe** protects the key, but it is a single device that
  must survive for decades, and anyone holding it and its PIN can use it.
- **A runbook of shell commands** is easy to get subtly wrong under pressure
  and hard to audit afterward.

coldroot is designed so that no single device, person, or piece of media has
to be trusted or has to survive:

- **The HSM is empty between ceremonies.** Keys live on the state disc,
  encrypted under a wrap key. The wrap key exists only as shares held by
  custodians (for example any 3 of 5). Each ceremony reconstructs it, loads
  the keys into an HSM, does its work, and wipes the HSM. No one can use the
  root alone, and losing an HSM or a couple of custodians loses nothing.
- **The ceremony machine is stateless.** It boots a RAM-only image from
  write-once optical media and has no disk. It reads OS, state, and request
  discs, and burns new state and output discs. Any compatible laptop and HSM
  can run a ceremony.
- **History is immutable.** State is never rewritten: each ceremony reads
  state disc *N* and burns state disc *N+1*. Old discs remain as a complete
  record.
- **The image is reproducible.** Anyone can rebuild the boot image from
  source and check that its hash matches the disc in the drive.
- **Ceremonies are driven, not typed.** A terminal UI walks the operator
  through each ceremony as a fixed sequence of steps with witness
  confirmations. Anything outside those sequences happens in an explicit
  exception mode that requires the quorum and is marked in the record.
- **Every ceremony leaves evidence.** Each action is appended to a
  hash-chained transcript that also links to the previous ceremony's
  transcript, so removing or altering anything is detectable.

## Who it is for

Small organizations, startups, and homelabs that want a root of trust with
real operational discipline, without an enterprise HSM budget. It targets the
YubiHSM 2 and commodity hardware.

coldroot is not an online CA. It produces and maintains the root and signs
intermediates for whatever online CA you run.

## Status

Early development. Not yet suitable for production keys.

## License

Licensed under the [Apache License, Version 2.0](LICENSE).
