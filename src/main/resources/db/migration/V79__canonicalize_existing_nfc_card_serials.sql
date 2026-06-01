-- V79: backfill — canonicalize existing nfc_cards.card_serial to the WS2 form.
--
-- WS2 (#159) added domain.model.NfcSerial.canonicalize() to BOTH NFC enrollment
-- AND the login lookup (NfcCardRepository.findByCardSerialAndUserIdAndIsActiveTrue),
-- normalizing every inbound serial to UPPER-HEX with no separators (or, for
-- non-hex/opaque serials, UPPER-CASE + trimmed with separators preserved). But it
-- never migrated rows enrolled BEFORE WS2, which stayed in their raw form (e.g.
-- the lowercase colon-separated "04:41:5d:42:0f:64:80"). After WS2 the canonicalizing
-- lookup searches for "04415D420F6480" and never matches the stale row, so a
-- previously-working enrolled card silently fails NFC login with
-- nfc_card_not_found_or_not_owned. (Regression confirmed live in prod 2026-06-01:
-- an enrolled, active İstanbulkart/student card no longer authenticated.)
--
-- This backfill applies the SAME canonicalization to existing rows so the stored
-- value matches what the lookup computes. Idempotent — already-canonical rows are
-- unchanged, so it is a no-op if the data was fixed out-of-band first. Mirrors
-- NfcSerial.canonicalize exactly:
--   strip [ : - . whitespace ]; if the stripped value is pure hex -> UPPER(stripped);
--   otherwise -> UPPER(TRIM(original)) with separators preserved.

UPDATE nfc_cards
SET card_serial = CASE
        WHEN regexp_replace(card_serial, '[:[:space:].-]', '', 'g') ~ '^[0-9A-Fa-f]+$'
            THEN upper(regexp_replace(card_serial, '[:[:space:].-]', '', 'g'))
        ELSE upper(trim(card_serial))
    END
WHERE card_serial <> CASE
        WHEN regexp_replace(card_serial, '[:[:space:].-]', '', 'g') ~ '^[0-9A-Fa-f]+$'
            THEN upper(regexp_replace(card_serial, '[:[:space:].-]', '', 'g'))
        ELSE upper(trim(card_serial))
    END;
