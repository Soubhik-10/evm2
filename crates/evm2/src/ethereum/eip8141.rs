use super::{
    effective_gas_price, initial_call_code, validate_block_gas_limit, validate_chain_id,
    validate_floor_gas, validate_gas_price, validate_nonce_not_overflow, validate_priority_fee,
    warm_base_accounts,
};
use crate::{
    EvmFeatures, EvmTypes, TxResult,
    bytecode::Bytecode,
    env::TxEnv,
    evm::{FrameTransactionResult, StateCheckpoint, error_handler},
    interpreter::{Host, InstrStop, Message, MessageKind},
    precompiles::{secp256k1, secp256r1},
    registry::{HandlerError, HandlerResult, TxRequest},
    utils::b256_to_word,
};
use alloc::vec::Vec;
use alloy_consensus::{TxEip8141, transaction::Recovered};
use alloy_eips::{
    eip4844::{DATA_GAS_PER_BLOB, VERSIONED_HASH_VERSION_KZG},
    eip8141::{
        APPROVE_SCOPE_MASK, ENTRY_POINT, EXPIRY_VERIFIER, EXPIRY_VERIFIER_RUNTIME, FrameMode,
        FrameReceipt, FrameStatus, MAX_FRAMES, SignatureScheme,
    },
};
use alloy_primitives::{Address, Bytes, KECCAK256_EMPTY, TxKind, U256, keccak256};

struct AtomicBatch {
    checkpoint: StateCheckpoint,
    approval: crate::evm::FrameApprovalState,
    warm_accesses: crate::evm::WarmAccessSnapshot,
    receipt_start: usize,
}

pub(super) fn handle<T: EvmTypes>(
    req: TxRequest<'_, '_, T, Recovered<TxEip8141>>,
) -> HandlerResult<TxResult<T>> {
    let tx = req.tx.inner();
    validate_structure(tx)?;

    let max_fee_per_gas = U256::from(tx.max_fee_per_gas);
    let max_priority_fee_per_gas = U256::from(tx.max_priority_fee_per_gas);
    let gas_price =
        effective_gas_price(max_fee_per_gas, max_priority_fee_per_gas, req.host.block.basefee);
    validate_priority_fee(req.host.version(), max_fee_per_gas, max_priority_fee_per_gas)?;
    validate_gas_price(req.host.version(), gas_price, req.host.block.basefee)?;
    validate_chain_id(req.host.version(), Some(tx.chain_id), false)?;
    validate_nonce_not_overflow(tx.nonce)?;

    let gas_limit = tx.calculate_gas_limit();
    let total_frame_gas = tx
        .frames
        .iter()
        .try_fold(0u64, |total, frame| total.checked_add(frame.gas_limit))
        .ok_or(HandlerError::InvalidFrameTransaction("total frame gas overflows u64"))?;
    let intrinsic = gas_limit
        .checked_sub(total_frame_gas)
        .ok_or(HandlerError::InvalidFrameTransaction("derived gas limit overflow"))?;
    let floor_gas = tx.calculate_calldata_floor();
    let gas_limit_cap = req.host.version().tx_gas_limit_cap;
    if gas_limit > gas_limit_cap {
        return Err(HandlerError::TxGasLimitGreaterThanCap { gas_limit, cap: gas_limit_cap });
    }
    validate_floor_gas(gas_limit, floor_gas)?;
    validate_block_gas_limit(req.host.version(), gas_limit, req.host.block.gas_limit)?;

    let blob_count = tx.blob_versioned_hashes.len();
    if blob_count > req.host.version().max_blobs_per_tx {
        return Err(HandlerError::TooManyBlobs {
            have: blob_count,
            max: req.host.version().max_blobs_per_tx,
        });
    }
    if tx.blob_versioned_hashes.iter().any(|hash| hash[0] != VERSIONED_HASH_VERSION_KZG) {
        return Err(HandlerError::BlobVersionNotSupported);
    }
    let max_fee_per_blob_gas = U256::from(tx.max_fee_per_blob_gas);
    if blob_count != 0 && max_fee_per_blob_gas < req.host.block.blob_basefee {
        return Err(HandlerError::BlobFeeCapLessThanBlobBaseFee {
            max_fee_per_blob_gas,
            blob_base_fee: req.host.block.blob_basefee,
        });
    }

    let sender_nonce =
        req.host.state.account(&tx.sender, false).map_err(error_handler!(req.host))?.nonce();
    if req.host.feature(EvmFeatures::NONCE_CHECK) && sender_nonce != tx.nonce {
        return Err(HandlerError::InvalidNonce { expected: sender_nonce, got: tx.nonce });
    }

    let signature_hash = tx.signature_hash();
    validate_signatures(tx, signature_hash)?;

    let blob_gas = U256::from(DATA_GAS_PER_BLOB) * U256::from(blob_count);
    let max_cost = U256::from(gas_limit)
        .saturating_mul(max_fee_per_gas)
        .saturating_add(blob_gas.saturating_mul(max_fee_per_blob_gas));
    req.host.begin_frame_transaction(tx.clone(), signature_hash, max_cost);

    warm_base_accounts(req.host, tx.sender, TxKind::Call(ENTRY_POINT));

    let tx_env_base = TxEnv {
        gas_price,
        chain_id: U256::from(req.host.version().chain_id),
        blob_hashes: tx.blob_versioned_hashes.iter().copied().map(b256_to_word).collect(),
        ext: T::TxEnvExt::default(),
        _non_exhaustive: (),
        ..TxEnv::default()
    };
    let mut receipts = Vec::with_capacity(tx.frames.len());
    let mut frame_state_gas = Vec::with_capacity(tx.frames.len());
    let mut frame_refunds = Vec::with_capacity(tx.frames.len());
    let mut batch: Option<AtomicBatch> = None;
    let mut frame_index = 0usize;

    while frame_index < tx.frames.len() {
        let frame = tx.frames[frame_index].clone();
        let resolved_target = tx
            .resolve_frame_target(&frame)
            .ok_or(HandlerError::InvalidFrameTransaction("invalid frame target"))?;
        if frame.mode == FrameMode::Sender && !req.host.frame_sender_approved() {
            return Err(HandlerError::InvalidFrameTransaction(
                "SENDER frame executed before execution approval",
            ));
        }
        if batch.is_none() && frame.is_atomic_batch() {
            batch = Some(AtomicBatch {
                checkpoint: req.host.state.checkpoint(),
                approval: req.host.frame_approval_state(),
                warm_accesses: req.host.state.warm_access_snapshot(),
                receipt_start: receipts.len(),
            });
        }

        req.host.set_current_transaction_frame(frame_index, resolved_target);
        let frame_checkpoint = req.host.state.checkpoint();
        let log_start = req.host.logs().len();
        let target_code_hash = match req.host.state.account(&resolved_target, false) {
            Ok(mut account) => {
                account.warm();
                account.code_hash()
            }
            Err(code) => return Err(HandlerError::Fatal(code)),
        };

        let mut initial_code = initial_call_code(req.host, resolved_target)?;
        if frame.mode == FrameMode::Verify && resolved_target == EXPIRY_VERIFIER {
            initial_code.code =
                Bytecode::new_legacy(Bytes::copy_from_slice(&EXPIRY_VERIFIER_RUNTIME));
            initial_code.code_address = EXPIRY_VERIFIER;
            initial_code.disable_precompiles = false;
        }
        // Default VERIFY behavior is selected from the resolved target's own code hash, before
        // EIP-7702 delegation resolution. The expiry verifier is treated as installed even when
        // the embedding host has not materialized the Bogota system-code transition.
        let uses_default_code = frame.mode == FrameMode::Verify
            && target_code_hash == KECCAK256_EMPTY
            && resolved_target != EXPIRY_VERIFIER;

        let (stop, frame_spent, state_gas, frame_refund) = if uses_default_code {
            let default_valid = frame.allowed_scope() != 0
                && tx.signatures.first().is_some_and(|signature| {
                    signature.scheme == SignatureScheme::Secp256k1
                        && signature.msg.is_empty()
                        && resolved_signature_signer(signature, tx.sender) == Some(resolved_target)
                });
            let stop = if default_valid {
                match req.host.approve_default_frame(resolved_target, frame.allowed_scope()) {
                    Ok(()) => InstrStop::Return,
                    Err(stop) => stop,
                }
            } else {
                InstrStop::Revert
            };
            (stop, 0, 0, 0)
        } else {
            let caller = if frame.mode == FrameMode::Sender { tx.sender } else { ENTRY_POINT };
            let tx_env = TxEnv { origin: caller, ..tx_env_base.clone() };
            let mut message = Message {
                kind: if frame.mode == FrameMode::Verify {
                    MessageKind::StaticCall
                } else {
                    MessageKind::Call
                },
                depth: 0,
                gas_limit: frame.gas_limit,
                reservoir: 0,
                destination: resolved_target,
                caller,
                input: frame.data.clone(),
                value: frame.value,
                code_address: initial_code.code_address,
                disable_precompiles: initial_code.disable_precompiles,
                caller_is_static: false,
                salt: Default::default(),
                ext: T::MessageExt::default(),
                _non_exhaustive: (),
            };
            let mut result = req.host.execute_message(&tx_env, initial_code.code, &mut message);
            if result.stop.is_halt() {
                // Top-level exceptional halts consume the frame's entire regular-gas
                // allocation; REVERT continues to preserve unused gas.
                result.gas.set_remaining(0);
            }
            let spent = frame
                .gas_limit
                .saturating_sub(result.gas.remaining())
                .saturating_sub(result.gas.reservoir());
            let state_gas = if result.stop.is_success() {
                result.gas.state_gas_spent().max(0) as u64
            } else {
                0
            };
            let refund =
                if result.stop.is_success() { result.gas.refunded().max(0) as u64 } else { 0 };
            (result.stop, spent, state_gas, refund)
        };

        if let Some(code) = req.host.error_code() {
            return Err(HandlerError::Fatal(code));
        }
        let success = stop.is_success();
        if success {
            req.host.commit_frame_root_approval();
            if let Some(atomic) = batch.as_mut() {
                atomic.warm_accesses = req.host.state.warm_access_snapshot();
            }
        } else {
            req.host.state.rollback(frame_checkpoint, req.host.version().features);
        }
        req.host.state.clear_transient_storage();

        if frame.mode == FrameMode::Verify && !success {
            return Err(HandlerError::InvalidFrameTransaction("VERIFY frame failed"));
        }

        let logs = if success { req.host.logs()[log_start..].to_vec() } else { Vec::new() };
        let status = if success { FrameStatus::Success } else { FrameStatus::Failure };
        receipts.push(FrameReceipt { status, gas_used: frame_spent, logs });
        frame_state_gas.push(state_gas);
        frame_refunds.push(frame_refund);
        req.host.record_frame_status(status);

        if !success {
            if let Some(atomic) = batch.take() {
                req.host.state.rollback(atomic.checkpoint, req.host.version().features);
                req.host.state.restore_warm_access_snapshot(&atomic.warm_accesses);
                req.host.restore_frame_approval_state(atomic.approval);
                req.host.state.clear_transient_storage();
                for index in atomic.receipt_start..receipts.len() {
                    receipts[index].status = FrameStatus::Failure;
                    receipts[index].logs.clear();
                    frame_state_gas[index] = 0;
                    frame_refunds[index] = 0;
                    req.host.replace_frame_status(index, FrameStatus::Failure);
                }
                let mut end = frame_index;
                while tx.frames[end].is_atomic_batch() {
                    end += 1;
                }
                for _ in frame_index + 1..=end {
                    receipts.push(FrameReceipt {
                        status: FrameStatus::SkippedAtomicBatch,
                        gas_used: 0,
                        logs: Vec::new(),
                    });
                    frame_state_gas.push(0);
                    frame_refunds.push(0);
                    req.host.record_frame_status(FrameStatus::SkippedAtomicBatch);
                }
                frame_index = end + 1;
                continue;
            }
        } else if !frame.is_atomic_batch() {
            batch = None;
        }
        frame_index += 1;
    }

    let payer = req
        .host
        .frame_payer()
        .ok_or(HandlerError::InvalidFrameTransaction("transaction did not approve a payer"))?;
    let total_frame_spent =
        receipts.iter().fold(0u64, |total, receipt| total.saturating_add(receipt.gas_used));
    let total_state_gas =
        frame_state_gas.into_iter().fold(0u64, |total, state_gas| total.saturating_add(state_gas));
    let refund_counter =
        frame_refunds.into_iter().fold(0u64, |total, refund| total.saturating_add(refund));
    let total_gas_spent = intrinsic.saturating_add(total_frame_spent);
    let refund_cap = if req.host.feature(EvmFeatures::EIP3529) {
        total_gas_spent / 5
    } else {
        total_gas_spent / 2
    };
    let refunded = refund_counter.min(refund_cap);
    let gas_used = total_gas_spent.saturating_sub(refunded).max(floor_gas);

    if req.host.feature(EvmFeatures::FEE_CHARGE) {
        let actual_cost = U256::from(gas_used)
            .saturating_mul(gas_price)
            .saturating_add(blob_gas.saturating_mul(req.host.block.blob_basefee));
        let payer_refund = max_cost.saturating_sub(actual_cost);
        req.host
            .state
            .account(&payer, false)
            .map_err(error_handler!(req.host))?
            .add_balance(payer_refund);

        let beneficiary_price = if req.host.feature(EvmFeatures::BASE_FEE_CHECK) {
            gas_price.saturating_sub(req.host.block.basefee)
        } else {
            gas_price
        };
        let beneficiary_reward = U256::from(gas_used).saturating_mul(beneficiary_price);
        let beneficiary = req.host.block.beneficiary;
        req.host
            .state
            .account(&beneficiary, false)
            .map_err(error_handler!(req.host))?
            .add_balance(beneficiary_reward);
    }

    Ok(TxResult {
        status: true,
        total_gas_spent,
        state_gas_spent: total_state_gas,
        refunded,
        floor_gas,
        stop: InstrStop::Stop,
        frame_result: Some(FrameTransactionResult { payer, frame_receipts: receipts }),
        ext: T::TxResultExt::default(),
        ..TxResult::default()
    })
}

fn validate_structure(tx: &TxEip8141) -> HandlerResult<()> {
    if tx.frames.is_empty() || tx.frames.len() > MAX_FRAMES {
        return Err(HandlerError::InvalidFrameTransaction("frame count must be in 1..=64"));
    }
    if tx.blob_versioned_hashes.is_empty() && tx.max_fee_per_blob_gas != 0 {
        return Err(HandlerError::InvalidFrameTransaction(
            "max blob fee must be zero without blobs",
        ));
    }
    let mut expiry_frames = 0usize;
    let mut total_gas = 0u64;
    for (index, frame) in tx.frames.iter().enumerate() {
        if frame.flags & !(APPROVE_SCOPE_MASK | 0x04) != 0 {
            return Err(HandlerError::InvalidFrameTransaction("reserved frame flag is set"));
        }
        if !frame.has_valid_target_encoding() {
            return Err(HandlerError::InvalidFrameTransaction(
                "frame target must be empty or 20 bytes",
            ));
        }
        if frame.mode != FrameMode::Sender && !frame.value.is_zero() {
            return Err(HandlerError::InvalidFrameTransaction(
                "only SENDER frames may transfer value",
            ));
        }
        total_gas = total_gas
            .checked_add(frame.gas_limit)
            .ok_or(HandlerError::InvalidFrameTransaction("total frame gas overflows u64"))?;
        if frame.allowed_scope() & 0x02 != 0 && tx.resolve_frame_target(frame) != Some(tx.sender) {
            return Err(HandlerError::InvalidFrameTransaction(
                "execution approval target must be the sender",
            ));
        }
        if frame.is_atomic_batch() && index + 1 == tx.frames.len() {
            return Err(HandlerError::InvalidFrameTransaction(
                "atomic batch flag cannot be set on the last frame",
            ));
        }
        if frame.mode == FrameMode::Verify && frame.target_address() == Some(EXPIRY_VERIFIER) {
            expiry_frames += 1;
            if !frame.is_expiry_verifier() {
                return Err(HandlerError::InvalidFrameTransaction(
                    "malformed expiry verifier frame",
                ));
            }
        }
    }
    if expiry_frames > 1 {
        return Err(HandlerError::InvalidFrameTransaction("multiple expiry verifier frames"));
    }

    for signature in &tx.signatures {
        match signature.scheme {
            SignatureScheme::Arbitrary if !signature.signer.is_empty() => {
                return Err(HandlerError::InvalidFrameTransaction(
                    "arbitrary signature signer must be empty",
                ));
            }
            SignatureScheme::Secp256k1 | SignatureScheme::P256
                if !signature.signer.is_empty() && signature.signer.len() != 20 =>
            {
                return Err(HandlerError::InvalidFrameTransaction(
                    "protocol signature signer must be empty or 20 bytes",
                ));
            }
            _ => {}
        }
        if signature.msg.len() != 0 && signature.msg.len() != 32 {
            return Err(HandlerError::InvalidFrameTransaction(
                "signature message must be empty or 32 bytes",
            ));
        }
        if signature.msg.len() == 32 && signature.msg.iter().all(|byte| *byte == 0) {
            return Err(HandlerError::InvalidFrameTransaction(
                "explicit signature message cannot be zero",
            ));
        }
    }
    Ok(())
}

fn validate_signatures(
    tx: &TxEip8141,
    signature_hash: alloy_primitives::B256,
) -> HandlerResult<()> {
    for signature in &tx.signatures {
        let message = if signature.msg.is_empty() {
            signature_hash
        } else {
            alloy_primitives::B256::from_slice(&signature.msg)
        };
        let signer = resolved_signature_signer(signature, tx.sender);
        let valid = match signature.scheme {
            SignatureScheme::Arbitrary => signature.signer.is_empty(),
            SignatureScheme::Secp256k1 => {
                if signature.signature.len() != 65 || signature.signature[0] > 1 {
                    false
                } else {
                    let mut rs = [0u8; 64];
                    rs.copy_from_slice(&signature.signature[1..]);
                    secp256k1::ecrecover_bytes(&rs, signature.signature[0], &message.0)
                        .map(|word| Address::from_slice(&word[12..]))
                        == signer
                }
            }
            SignatureScheme::P256 => {
                if signature.signature.len() != 128 {
                    false
                } else {
                    let public_key = &signature.signature[64..128];
                    let key_address = Address::from_slice(&keccak256(public_key)[12..]);
                    let mut input = [0u8; 160];
                    input[..32].copy_from_slice(message.as_slice());
                    input[32..].copy_from_slice(&signature.signature);
                    signer == Some(key_address) && secp256r1::verify_impl(&input)
                }
            }
        };
        if !valid {
            return Err(HandlerError::InvalidFrameTransaction("signature validation failed"));
        }
    }
    Ok(())
}

fn resolved_signature_signer(
    signature: &alloy_eips::eip8141::FrameSignature,
    sender: Address,
) -> Option<Address> {
    if signature.scheme == SignatureScheme::Arbitrary {
        None
    } else if signature.signer.is_empty() {
        Some(sender)
    } else {
        signature.signer_address()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        BaseEvmTypes, Evm, Precompiles, SpecId,
        bytecode::Bytecode,
        env::BlockEnv,
        ethereum::{RecoveredTxEnvelope, ethereum_tx_registry},
        evm::{AccountInfo, InMemoryDB},
        interpreter::{Word, op},
    };
    use alloc::vec;
    use alloy_eips::eip8141::{ApprovalScope, Frame, FrameSignature};
    use alloy_primitives::{Bytes, U256};
    use k256::ecdsa::SigningKey;

    const BALANCE: u64 = 10_000_000;

    fn signer() -> (SigningKey, Address) {
        let key = SigningKey::from_slice(&[0x11; 32]).unwrap();
        let public_key = key.verifying_key().to_encoded_point(false);
        let address = Address::from_raw_public_key(&public_key.as_bytes()[1..]);
        (key, address)
    }

    fn sign(tx: TxEip8141, key: &SigningKey) -> TxEip8141 {
        sign_with_additional_signatures(tx, key, Vec::new())
    }

    fn sign_with_additional_signatures(
        mut tx: TxEip8141,
        key: &SigningKey,
        additional: Vec<FrameSignature>,
    ) -> TxEip8141 {
        tx.signatures = vec![FrameSignature {
            scheme: SignatureScheme::Secp256k1,
            signer: Bytes::new(),
            msg: Bytes::new(),
            signature: Bytes::from(vec![0; 65]),
        }];
        tx.signatures.extend(additional);
        let (signature, recovery_id) =
            key.sign_prehash_recoverable(tx.signature_hash().as_slice()).unwrap();
        let mut encoded = Vec::with_capacity(65);
        encoded.push(recovery_id.to_byte());
        let signature_bytes = signature.to_bytes();
        encoded.extend_from_slice(&signature_bytes);
        tx.signatures[0].signature = encoded.into();
        tx
    }

    fn envelope(tx: TxEip8141) -> RecoveredTxEnvelope {
        let sender = tx.sender;
        RecoveredTxEnvelope::Eip8141(Recovered::new_unchecked(tx, sender))
    }

    fn evm(database: InMemoryDB) -> Evm<'static, BaseEvmTypes> {
        Evm::new(
            SpecId::BOGOTA,
            BlockEnv::default(),
            ethereum_tx_registry(SpecId::BOGOTA),
            database,
            Precompiles::base(SpecId::BOGOTA),
        )
    }

    fn default_verify(gas_limit: u64) -> Frame {
        Frame {
            mode: FrameMode::Verify,
            flags: ApprovalScope::ExecutionAndPayment.into(),
            target: Bytes::new(),
            gas_limit,
            value: U256::ZERO,
            data: Bytes::new(),
        }
    }

    #[test]
    fn default_account_approves_execution_and_payment() {
        let (key, sender) = signer();
        let mut database = InMemoryDB::default();
        database
            .insert_account_info(&sender, AccountInfo::default().with_balance(Word::from(BALANCE)));
        let tx = sign(
            TxEip8141 {
                chain_id: 1,
                sender,
                // The frame allocation also leaves enough derived gas to cover the EIP-7623 floor.
                frames: vec![default_verify(1_000)],
                max_fee_per_gas: 1,
                ..Default::default()
            },
            &key,
        );
        let mut evm = evm(database);

        let result = evm.transact(&envelope(tx)).unwrap().commit();

        assert!(result.status);
        let frame_result = result.frame_result.unwrap();
        assert_eq!(frame_result.payer, sender);
        assert_eq!(frame_result.frame_receipts.len(), 1);
        assert_eq!(frame_result.frame_receipts[0].status, FrameStatus::Success);
        assert_eq!(evm.read_account_info(&sender).unwrap().unwrap().nonce, 1);
    }

    #[test]
    fn rejects_derived_gas_limit_above_bogota_cap() {
        let (_, sender) = signer();
        let cap = crate::Version::base(SpecId::BOGOTA).tx_gas_limit_cap;
        let tx = TxEip8141 {
            chain_id: 1,
            sender,
            frames: vec![default_verify(cap)],
            ..Default::default()
        };
        let gas_limit = tx.calculate_gas_limit();
        let mut evm = evm(InMemoryDB::default());

        let error = evm.transact(&envelope(tx)).unwrap_err();

        assert_eq!(error, HandlerError::TxGasLimitGreaterThanCap { gas_limit, cap });
    }

    #[test]
    fn rejects_calldata_floor_above_derived_gas_limit() {
        let (_, sender) = signer();
        let tx = TxEip8141 {
            chain_id: 1,
            sender,
            frames: vec![Frame::default()],
            signatures: vec![FrameSignature {
                scheme: SignatureScheme::Arbitrary,
                signature: Bytes::from(vec![0; 2_048]),
                ..Default::default()
            }],
            ..Default::default()
        };
        let gas_limit = tx.calculate_gas_limit();
        let floor_gas = tx.calculate_calldata_floor();
        assert!(floor_gas > gas_limit);
        let mut evm = evm(InMemoryDB::default());

        let error = evm.transact(&envelope(tx)).unwrap_err();

        assert_eq!(error, HandlerError::IntrinsicGasTooLow { required: floor_gas, got: gas_limit });
    }

    #[test]
    fn failed_atomic_batch_rolls_back_prior_success_and_marks_receipts() {
        let (key, sender) = signer();
        let writer = Address::from([0x22; 20]);
        let reverter = Address::from([0x33; 20]);
        let writer_code = Bytecode::new_legacy(Bytes::from_static(&[
            op::PUSH1,
            1,
            op::PUSH0,
            op::SSTORE,
            op::STOP,
        ]));
        let revert_code =
            Bytecode::new_legacy(Bytes::from_static(&[op::PUSH0, op::PUSH0, op::REVERT]));
        let mut database = InMemoryDB::default();
        database
            .insert_account_info(&sender, AccountInfo::default().with_balance(Word::from(BALANCE)));
        database.insert_account_info(&writer, AccountInfo::default().with_code(writer_code));
        database.insert_account_info(&reverter, AccountInfo::default().with_code(revert_code));
        let tx = sign(
            TxEip8141 {
                chain_id: 1,
                sender,
                frames: vec![
                    default_verify(0),
                    Frame {
                        mode: FrameMode::Sender,
                        flags: 0x04,
                        target: Bytes::copy_from_slice(writer.as_slice()),
                        gas_limit: 150_000,
                        ..Default::default()
                    },
                    Frame {
                        mode: FrameMode::Sender,
                        flags: 0x04,
                        target: Bytes::copy_from_slice(reverter.as_slice()),
                        gas_limit: 20_000,
                        ..Default::default()
                    },
                    Frame { mode: FrameMode::Sender, gas_limit: 10_000, ..Default::default() },
                ],
                max_fee_per_gas: 1,
                ..Default::default()
            },
            &key,
        );
        let mut evm = evm(database);

        let result = evm.transact(&envelope(tx)).unwrap().commit();

        assert_eq!(result.state_gas_spent, 0);
        let receipts = result.frame_result.unwrap().frame_receipts;
        assert_eq!(
            receipts.iter().map(|receipt| receipt.status).collect::<Vec<_>>(),
            [
                FrameStatus::Success,
                FrameStatus::Failure,
                FrameStatus::Failure,
                FrameStatus::SkippedAtomicBatch,
            ]
        );
        assert_eq!(
            evm.state_mut().read_committed_storage(&writer, &Word::ZERO).unwrap(),
            Word::ZERO
        );
    }

    #[test]
    fn failed_atomic_batch_retains_accesses_from_prior_successful_frame() {
        let (key, sender) = signer();
        let first_reader = Address::from([0x71; 20]);
        let reverter = Address::from([0x72; 20]);
        let second_reader = Address::from([0x73; 20]);
        let observed = Address::from([0x74; 20]);
        let mut reader_code = vec![op::PUSH20];
        reader_code.extend_from_slice(observed.as_slice());
        reader_code.extend_from_slice(&[op::BALANCE, op::POP, op::STOP]);
        let reader_code = Bytecode::new_legacy(reader_code.into());
        let revert_code =
            Bytecode::new_legacy(Bytes::from_static(&[op::PUSH0, op::PUSH0, op::REVERT]));
        let mut database = InMemoryDB::default();
        database
            .insert_account_info(&sender, AccountInfo::default().with_balance(Word::from(BALANCE)));
        database.insert_account_info(
            &first_reader,
            AccountInfo::default().with_code(reader_code.clone()),
        );
        database.insert_account_info(&reverter, AccountInfo::default().with_code(revert_code));
        database.insert_account_info(&second_reader, AccountInfo::default().with_code(reader_code));
        let tx = sign(
            TxEip8141 {
                chain_id: 1,
                sender,
                frames: vec![
                    default_verify(0),
                    Frame {
                        mode: FrameMode::Sender,
                        flags: 0x04,
                        target: Bytes::copy_from_slice(first_reader.as_slice()),
                        gas_limit: 10_000,
                        ..Default::default()
                    },
                    Frame {
                        mode: FrameMode::Sender,
                        target: Bytes::copy_from_slice(reverter.as_slice()),
                        gas_limit: 10_000,
                        ..Default::default()
                    },
                    Frame {
                        mode: FrameMode::Sender,
                        target: Bytes::copy_from_slice(second_reader.as_slice()),
                        gas_limit: 10_000,
                        ..Default::default()
                    },
                ],
                max_fee_per_gas: 1,
                ..Default::default()
            },
            &key,
        );
        let mut evm = evm(database);

        let result = evm.transact(&envelope(tx)).unwrap().commit();

        let receipts = result.frame_result.unwrap().frame_receipts;
        assert_eq!(receipts[1].status, FrameStatus::Failure);
        assert_eq!(receipts[2].status, FrameStatus::Failure);
        // PUSH20 (3) + warm BALANCE (100) + POP (2).
        assert_eq!(receipts[3].gas_used, 105);
    }

    #[test]
    fn exceptional_halt_consumes_entire_frame_gas_limit() {
        let (key, sender) = signer();
        let target = Address::from([0x55; 20]);
        let frame_gas_limit = 12_345;
        let mut database = InMemoryDB::default();
        database
            .insert_account_info(&sender, AccountInfo::default().with_balance(Word::from(BALANCE)));
        database.insert_account_info(
            &target,
            AccountInfo::default()
                .with_code(Bytecode::new_legacy(Bytes::from_static(&[op::INVALID]))),
        );
        let tx = sign(
            TxEip8141 {
                chain_id: 1,
                sender,
                frames: vec![
                    default_verify(0),
                    Frame {
                        mode: FrameMode::Sender,
                        target: Bytes::copy_from_slice(target.as_slice()),
                        gas_limit: frame_gas_limit,
                        ..Default::default()
                    },
                ],
                max_fee_per_gas: 1,
                ..Default::default()
            },
            &key,
        );
        let mut evm = evm(database);

        let result = evm.transact(&envelope(tx)).unwrap().commit();

        let receipts = result.frame_result.unwrap().frame_receipts;
        assert_eq!(receipts[1].status, FrameStatus::Failure);
        assert_eq!(receipts[1].gas_used, frame_gas_limit);
    }

    #[test]
    fn sigparam_copy_mode_charges_calldatacopy_base_gas() {
        let (key, sender) = signer();
        let target = Address::from([0x66; 20]);
        // Copy zero bytes from arbitrary signature index 1. PUSH0 costs 2, PUSH1 costs 3, and
        // SIGPARAM copy mode costs 3: 3 * 2 + 2 * 3 + 3 = 15 gas.
        let code = Bytecode::new_legacy(Bytes::from_static(&[
            op::PUSH0,
            op::PUSH0,
            op::PUSH0,
            op::PUSH1,
            4,
            op::PUSH1,
            1,
            op::SIGPARAM,
            op::STOP,
        ]));
        let mut database = InMemoryDB::default();
        database
            .insert_account_info(&sender, AccountInfo::default().with_balance(Word::from(BALANCE)));
        database.insert_account_info(&target, AccountInfo::default().with_code(code));
        let tx = sign_with_additional_signatures(
            TxEip8141 {
                chain_id: 1,
                sender,
                frames: vec![
                    default_verify(0),
                    Frame {
                        target: Bytes::copy_from_slice(target.as_slice()),
                        // The opcode consumes 15 gas; the unused allocation keeps the derived
                        // transaction gas limit above its EIP-7623 calldata floor.
                        gas_limit: 10_000,
                        ..Default::default()
                    },
                ],
                max_fee_per_gas: 1,
                ..Default::default()
            },
            &key,
            vec![FrameSignature {
                scheme: SignatureScheme::Arbitrary,
                signature: Bytes::from_static(&[0xaa, 0xbb, 0xcc]),
                ..Default::default()
            }],
        );
        let mut evm = evm(database);

        let result = evm.transact(&envelope(tx)).unwrap().commit();

        let receipts = result.frame_result.unwrap().frame_receipts;
        assert_eq!(receipts[1].status, FrameStatus::Success);
        assert_eq!(receipts[1].gas_used, 15);
    }

    #[test]
    fn approval_in_reverted_parent_call_does_not_leak() {
        let (_, sender) = signer();
        let library = Address::from([0x44; 20]);
        let mut parent = vec![op::PUSH0, op::PUSH0, op::PUSH0, op::PUSH0, op::PUSH20];
        parent.extend_from_slice(library.as_slice());
        parent.extend_from_slice(&[
            op::PUSH2,
            0xff,
            0xff,
            op::DELEGATECALL,
            op::PUSH0,
            op::PUSH0,
            op::REVERT,
        ]);
        let library_code = Bytecode::new_legacy(Bytes::from_static(&[
            op::PUSH1,
            3,
            op::PUSH0,
            op::PUSH0,
            op::APPROVE,
        ]));
        let mut database = InMemoryDB::default();
        database.insert_account_info(
            &sender,
            AccountInfo::default()
                .with_balance(Word::from(BALANCE))
                .with_code(Bytecode::new_legacy(parent.into())),
        );
        database.insert_account_info(&library, AccountInfo::default().with_code(library_code));
        let tx = TxEip8141 {
            chain_id: 1,
            sender,
            frames: vec![
                Frame { flags: 3, gas_limit: 100_000, ..Default::default() },
                Frame { mode: FrameMode::Sender, gas_limit: 1, ..Default::default() },
            ],
            max_fee_per_gas: 1,
            ..Default::default()
        };
        let mut evm = evm(database);

        let error = evm.transact(&envelope(tx)).unwrap_err();

        assert_eq!(
            error,
            HandlerError::InvalidFrameTransaction(
                "SENDER frame executed before execution approval"
            )
        );
        assert_eq!(evm.read_account_info(&sender).unwrap().unwrap().nonce, 0);
    }
}
