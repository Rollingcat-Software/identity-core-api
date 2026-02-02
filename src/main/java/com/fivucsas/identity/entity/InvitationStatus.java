package com.fivucsas.identity.entity;

/**
 * Status of a guest invitation through its lifecycle.
 */
public enum InvitationStatus {
    /** Invitation sent, awaiting acceptance. */
    PENDING,
    /** Invitation accepted, guest user created. */
    ACCEPTED,
    /** Invitation expired without acceptance, or guest access window ended. */
    EXPIRED,
    /** Invitation explicitly revoked by tenant admin. */
    REVOKED
}
