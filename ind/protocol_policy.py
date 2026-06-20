"""Runtime policy for the active IND bill protocol generation."""

V3_BILL_MESSAGE_TYPES = {
    "ind.bill.v3",
    "ind.transfer_announcement.v3",
    "ind.checkpoint_announcement.v3",
    "ind.proof_bundle_announcement.v3",
    "ind.archive_segment_announcement.v3",
    "ind.conflict_proof.v3",
}


def is_v3_bill_message_type(message_type):
    return str(message_type) in V3_BILL_MESSAGE_TYPES


def non_v3_disabled_message(operation="non-V3 bill protocol"):
    return f"{operation} is rejected; V3 is the only active bill protocol"
