"""Runtime policy for the active IND bill protocol generation."""

LEGACY_BILL_MESSAGE_TYPES = set()

V3_BILL_MESSAGE_TYPES = {
    "ind.bill.v3",
    "ind.transfer_announcement.v3",
    "ind.checkpoint_announcement.v3",
    "ind.proof_bundle_announcement.v3",
    "ind.archive_segment_announcement.v3",
    "ind.conflict_proof.v3",
}


def is_legacy_bill_message_type(message_type):
    return str(message_type) in LEGACY_BILL_MESSAGE_TYPES


def is_v3_bill_message_type(message_type):
    return str(message_type) in V3_BILL_MESSAGE_TYPES


def legacy_disabled_message(operation="legacy bill protocol"):
    return f"{operation} is disabled; V3 is the only active bill protocol"
