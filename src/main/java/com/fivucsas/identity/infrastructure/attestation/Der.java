package com.fivucsas.identity.infrastructure.attestation;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**
 * Minimal, strict DER reader used to parse the Android Key Attestation
 * {@code KeyDescription} extension (OID 1.3.6.1.4.1.11129.2.1.17).
 *
 * <p>BouncyCastle is not on this module's classpath, and the structure we need is
 * small, so this is a deliberately tiny parser: definite lengths only, minimal
 * length encoding, high-tag-number form supported (the AuthorizationList uses
 * context tags up to 7xx), bounded nesting depth. Anything else throws
 * {@link DerException}; callers treat that as a failed attestation (fail closed).
 */
final class Der {

    static final int CLASS_UNIVERSAL = 0;
    static final int CLASS_CONTEXT = 2;

    static final int TAG_BOOLEAN = 1;
    static final int TAG_INTEGER = 2;
    static final int TAG_OCTET_STRING = 4;
    static final int TAG_NULL = 5;
    static final int TAG_ENUMERATED = 10;
    static final int TAG_SEQUENCE = 16;
    static final int TAG_SET = 17;

    private static final int MAX_DEPTH = 32;

    private Der() {
    }

    /** Thrown on any malformed or non-DER input. */
    static final class DerException extends Exception {
        DerException(String message) {
            super(message);
        }
    }

    /** One decoded TLV. {@code content} is a copy of the value bytes. */
    record Value(int tagClass, boolean constructed, int tagNumber, byte[] content, int depth) {

        boolean is(int cls, int number) {
            return tagClass == cls && tagNumber == number;
        }

        List<Value> children() throws DerException {
            if (!constructed) {
                throw new DerException("not a constructed value (tag " + tagNumber + ")");
            }
            return readAll(content, depth + 1);
        }

        Value expectUniversal(int number) throws DerException {
            if (!is(CLASS_UNIVERSAL, number)) {
                throw new DerException("expected universal tag " + number + " but got class "
                        + tagClass + " tag " + tagNumber);
            }
            return this;
        }

        BigInteger integer() throws DerException {
            if (constructed || content.length == 0) {
                throw new DerException("bad INTEGER/ENUMERATED");
            }
            if (content.length > 1
                    && ((content[0] == 0 && (content[1] & 0x80) == 0)
                    || (content[0] == (byte) 0xFF && (content[1] & 0x80) != 0))) {
                throw new DerException("non-minimal INTEGER encoding");
            }
            return new BigInteger(content);
        }

        /** INTEGER or ENUMERATED that must fit in a non-negative long. */
        long nonNegativeLong() throws DerException {
            BigInteger v = integer();
            if (v.signum() < 0 || v.bitLength() > 63) {
                throw new DerException("integer out of range");
            }
            return v.longValue();
        }

        byte[] octets() throws DerException {
            if (constructed) {
                throw new DerException("constructed OCTET STRING not allowed in DER");
            }
            return content.clone();
        }

        boolean bool() throws DerException {
            if (constructed || content.length != 1) {
                throw new DerException("bad BOOLEAN length");
            }
            if (content[0] == 0) {
                return false;
            }
            if (content[0] == (byte) 0xFF) {
                return true;
            }
            throw new DerException("non-DER BOOLEAN value");
        }

        /** The single inner value of an EXPLICIT context tag. */
        Value explicitInner() throws DerException {
            List<Value> inner = children();
            if (inner.size() != 1) {
                throw new DerException("explicit tag must wrap exactly one value");
            }
            return inner.get(0);
        }
    }

    /** Parses exactly one value that must span the whole buffer. */
    static Value readSingle(byte[] data) throws DerException {
        List<Value> all = readAll(data, 0);
        if (all.size() != 1) {
            throw new DerException("expected exactly one top-level value, got " + all.size());
        }
        return all.get(0);
    }

    static List<Value> readAll(byte[] data, int depth) throws DerException {
        if (depth > MAX_DEPTH) {
            throw new DerException("nesting too deep");
        }
        List<Value> out = new ArrayList<>();
        int pos = 0;
        while (pos < data.length) {
            int first = data[pos++] & 0xFF;
            int tagClass = first >>> 6;
            boolean constructed = (first & 0x20) != 0;
            int tagNumber = first & 0x1F;
            if (tagNumber == 0x1F) {
                // High-tag-number form: base-128, no leading 0x80 octet.
                tagNumber = 0;
                int count = 0;
                while (true) {
                    if (pos >= data.length) {
                        throw new DerException("truncated tag");
                    }
                    int b = data[pos++] & 0xFF;
                    if (count == 0 && b == 0x80) {
                        throw new DerException("non-minimal tag encoding");
                    }
                    if (++count > 4) {
                        throw new DerException("tag number too large");
                    }
                    tagNumber = (tagNumber << 7) | (b & 0x7F);
                    if ((b & 0x80) == 0) {
                        break;
                    }
                }
                if (tagNumber < 0x1F) {
                    throw new DerException("high-tag form used for a low tag number");
                }
            }
            if (pos >= data.length) {
                throw new DerException("truncated length");
            }
            int lenByte = data[pos++] & 0xFF;
            int length;
            if (lenByte < 0x80) {
                length = lenByte;
            } else if (lenByte == 0x80) {
                throw new DerException("indefinite length not allowed in DER");
            } else {
                int n = lenByte & 0x7F;
                if (n > 4) {
                    throw new DerException("length too large");
                }
                if (pos + n > data.length) {
                    throw new DerException("truncated length");
                }
                if ((data[pos] & 0xFF) == 0) {
                    throw new DerException("non-minimal length encoding");
                }
                long l = 0;
                for (int i = 0; i < n; i++) {
                    l = (l << 8) | (data[pos++] & 0xFF);
                }
                if (l < 0x80 || l > Integer.MAX_VALUE) {
                    throw new DerException("non-minimal or oversized length");
                }
                length = (int) l;
            }
            if (length > data.length - pos) {
                throw new DerException("value exceeds buffer");
            }
            byte[] content = Arrays.copyOfRange(data, pos, pos + length);
            pos += length;
            out.add(new Value(tagClass, constructed, tagNumber, content, depth));
        }
        return out;
    }
}
