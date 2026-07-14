use super::Evm;
use crate::{
    ErrorCode, EvmFeatures, EvmTypes,
    interpreter::{InstrStop, Word},
    utils::{address_to_word, b256_to_word, word_to_usize},
};
use alloc::vec::Vec;
use alloy_consensus::TxEip8141;
use alloy_eips::eip8141::{FrameStatus, SignatureScheme};
use alloy_primitives::{Address, B256, Bytes, U256};

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct FrameApprovalState {
    pub(crate) payer: Option<Address>,
    pub(crate) sender_approved: bool,
}

#[derive(Clone, Debug)]
pub(crate) struct FrameTransactionContext {
    pub(crate) tx: TxEip8141,
    pub(crate) signature_hash: B256,
    pub(crate) max_cost: U256,
    pub(crate) approval: FrameApprovalState,
    pub(crate) current_frame_index: usize,
    pub(crate) resolved_target: Address,
    pub(crate) statuses: Vec<FrameStatus>,
}

impl<'a, T: EvmTypes> Evm<'a, T> {
    pub(crate) fn begin_frame_transaction(
        &mut self,
        tx: TxEip8141,
        signature_hash: B256,
        max_cost: U256,
    ) {
        self.frame_approval_stack.clear();
        self.frame_root_approval = None;
        self.frame_tx = Some(FrameTransactionContext {
            resolved_target: tx.sender,
            tx,
            signature_hash,
            max_cost,
            approval: FrameApprovalState::default(),
            current_frame_index: 0,
            statuses: Vec::new(),
        });
    }

    pub(crate) fn clear_frame_transaction_context(&mut self) {
        self.frame_tx = None;
        self.frame_approval_stack.clear();
        self.frame_root_approval = None;
    }

    pub(crate) fn set_current_transaction_frame(
        &mut self,
        frame_index: usize,
        resolved_target: Address,
    ) {
        let context = self.frame_tx.as_mut().expect("frame transaction context is active");
        context.current_frame_index = frame_index;
        context.resolved_target = resolved_target;
        self.frame_root_approval = None;
        self.frame_approval_stack.clear();
    }

    pub(crate) fn frame_approval_state(&self) -> FrameApprovalState {
        self.frame_tx.as_ref().expect("frame transaction context is active").approval
    }

    pub(crate) fn restore_frame_approval_state(&mut self, approval: FrameApprovalState) {
        self.frame_tx.as_mut().expect("frame transaction context is active").approval = approval;
        self.frame_root_approval = None;
        self.frame_approval_stack.clear();
    }

    pub(crate) fn frame_sender_approved(&self) -> bool {
        self.frame_approval_state().sender_approved
    }

    pub(crate) fn frame_payer(&self) -> Option<Address> {
        self.frame_approval_state().payer
    }

    pub(crate) fn record_frame_status(&mut self, status: FrameStatus) {
        self.frame_tx.as_mut().expect("frame transaction context is active").statuses.push(status);
    }

    pub(crate) fn replace_frame_status(&mut self, index: usize, status: FrameStatus) {
        self.frame_tx.as_mut().expect("frame transaction context is active").statuses[index] =
            status;
    }

    /// Starts an approval journal scope for one interpreter call frame.
    pub(crate) fn enter_frame_approval_scope(&mut self) -> bool {
        let Some(context) = self.frame_tx.as_ref() else { return false };
        let approval = self.frame_approval_stack.last().copied().unwrap_or(context.approval);
        self.frame_approval_stack.push(approval);
        true
    }

    /// Commits a successful nested approval scope into its parent and discards a failed scope.
    pub(crate) fn exit_frame_approval_scope(&mut self, entered: bool, success: bool) {
        if !entered {
            return;
        }
        let approval = self.frame_approval_stack.pop().expect("approval scope is balanced");
        if !success {
            return;
        }
        if let Some(parent) = self.frame_approval_stack.last_mut() {
            *parent = approval;
        } else {
            self.frame_root_approval = Some(approval);
        }
    }

    pub(crate) fn commit_frame_root_approval(&mut self) {
        if let Some(approval) = self.frame_root_approval.take() {
            self.frame_tx.as_mut().expect("frame transaction context is active").approval =
                approval;
        }
    }

    pub(crate) fn approve_default_frame(
        &mut self,
        current_target: Address,
        scope: u8,
    ) -> Result<(), InstrStop> {
        let entered = self.enter_frame_approval_scope();
        let result = self.approve_transaction_frame(current_target, Word::from(scope));
        self.exit_frame_approval_scope(entered, result.is_ok());
        if result.is_ok() {
            self.commit_frame_root_approval();
        }
        result
    }

    pub(crate) fn transaction_frame_param(&self, param: Word) -> Result<Word, InstrStop> {
        let context = self.frame_tx.as_ref().ok_or(InstrStop::InvalidOpcode)?;
        Ok(match param.to::<u64>() {
            0x00 if param <= Word::from(u64::MAX) => Word::from(0x06),
            0x01 if param <= Word::from(u64::MAX) => Word::from(context.tx.nonce),
            0x02 if param <= Word::from(u64::MAX) => address_to_word(&context.tx.sender),
            0x03 if param <= Word::from(u64::MAX) => {
                Word::from(context.tx.max_priority_fee_per_gas)
            }
            0x04 if param <= Word::from(u64::MAX) => Word::from(context.tx.max_fee_per_gas),
            0x05 if param <= Word::from(u64::MAX) => Word::from(context.tx.max_fee_per_blob_gas),
            0x06 if param <= Word::from(u64::MAX) => context.max_cost,
            0x07 if param <= Word::from(u64::MAX) => {
                Word::from(context.tx.blob_versioned_hashes.len())
            }
            0x08 if param <= Word::from(u64::MAX) => b256_to_word(context.signature_hash),
            0x09 if param <= Word::from(u64::MAX) => Word::from(context.tx.frames.len()),
            0x0a if param <= Word::from(u64::MAX) => Word::from(context.current_frame_index),
            0x0b if param <= Word::from(u64::MAX) => Word::from(context.tx.signatures.len()),
            _ => return Err(InstrStop::InvalidOpcode),
        })
    }

    pub(crate) fn transaction_frame_data(&self, frame_index: Word) -> Result<Bytes, InstrStop> {
        let index = word_to_usize(frame_index)?;
        self.frame_tx
            .as_ref()
            .ok_or(InstrStop::InvalidOpcode)?
            .tx
            .frames
            .get(index)
            .map(|frame| frame.data.clone())
            .ok_or(InstrStop::InvalidOpcode)
    }

    pub(crate) fn transaction_frame_metadata(
        &self,
        frame_index: Word,
        param: Word,
    ) -> Result<Word, InstrStop> {
        let index = word_to_usize(frame_index)?;
        let context = self.frame_tx.as_ref().ok_or(InstrStop::InvalidOpcode)?;
        let frame = context.tx.frames.get(index).ok_or(InstrStop::InvalidOpcode)?;
        Ok(match param.to::<u64>() {
            0x00 if param <= Word::from(u64::MAX) => address_to_word(
                &context.tx.resolve_frame_target(frame).ok_or(InstrStop::InvalidOpcode)?,
            ),
            0x01 if param <= Word::from(u64::MAX) => Word::from(frame.gas_limit),
            0x02 if param <= Word::from(u64::MAX) => Word::from(u8::from(frame.mode)),
            0x03 if param <= Word::from(u64::MAX) => Word::from(frame.flags),
            0x04 if param <= Word::from(u64::MAX) => Word::from(frame.data.len()),
            0x05 if param <= Word::from(u64::MAX) => {
                if index >= context.current_frame_index {
                    return Err(InstrStop::InvalidOpcode);
                }
                Word::from(u8::from(*context.statuses.get(index).ok_or(InstrStop::InvalidOpcode)?))
            }
            0x06 if param <= Word::from(u64::MAX) => Word::from(frame.allowed_scope()),
            0x07 if param <= Word::from(u64::MAX) => Word::from(frame.is_atomic_batch()),
            0x08 if param <= Word::from(u64::MAX) => frame.value,
            _ => return Err(InstrStop::InvalidOpcode),
        })
    }

    pub(crate) fn transaction_signature_metadata(
        &self,
        signature_index: Word,
        param: Word,
    ) -> Result<Word, InstrStop> {
        let index = word_to_usize(signature_index)?;
        let context = self.frame_tx.as_ref().ok_or(InstrStop::InvalidOpcode)?;
        let signature = context.tx.signatures.get(index).ok_or(InstrStop::InvalidOpcode)?;
        Ok(match param.to::<u64>() {
            0x00 if param <= Word::from(u64::MAX) => {
                if signature.scheme == SignatureScheme::Arbitrary {
                    return Err(InstrStop::InvalidOpcode);
                }
                let signer = if signature.signer.is_empty() {
                    context.tx.sender
                } else {
                    signature.signer_address().ok_or(InstrStop::InvalidOpcode)?
                };
                address_to_word(&signer)
            }
            0x01 if param <= Word::from(u64::MAX) => Word::from(u8::from(signature.scheme)),
            0x02 if param <= Word::from(u64::MAX) => {
                if signature.msg.is_empty() {
                    Word::ZERO
                } else {
                    Word::from_be_slice(&signature.msg)
                }
            }
            0x03 if param <= Word::from(u64::MAX) => Word::from(signature.signature.len()),
            _ => return Err(InstrStop::InvalidOpcode),
        })
    }

    pub(crate) fn transaction_signature_bytes(
        &self,
        signature_index: Word,
    ) -> Result<Bytes, InstrStop> {
        let index = word_to_usize(signature_index)?;
        let signature = self
            .frame_tx
            .as_ref()
            .ok_or(InstrStop::InvalidOpcode)?
            .tx
            .signatures
            .get(index)
            .ok_or(InstrStop::InvalidOpcode)?;
        if signature.scheme != SignatureScheme::Arbitrary {
            return Err(InstrStop::InvalidOpcode);
        }
        Ok(signature.signature.clone())
    }

    pub(crate) fn approve_transaction_frame(
        &mut self,
        current_target: Address,
        scope: Word,
    ) -> Result<(), InstrStop> {
        let Some(context) = self.frame_tx.as_ref() else {
            return Err(InstrStop::InvalidOpcode);
        };
        if scope > Word::from(u8::MAX) || current_target != context.resolved_target {
            return Err(InstrStop::Revert);
        }
        let scope = scope.to::<u8>();
        let frame = &context.tx.frames[context.current_frame_index];
        if scope == 0 || scope & !frame.allowed_scope() != 0 {
            return Err(InstrStop::Revert);
        }

        let current = self.frame_approval_stack.last().copied().unwrap_or(context.approval);
        let approves_payment = scope & 0x01 != 0;
        let approves_execution = scope & 0x02 != 0;
        if approves_execution
            && (current.sender_approved || context.resolved_target != context.tx.sender)
        {
            return Err(InstrStop::Revert);
        }
        if approves_payment
            && (current.payer.is_some() || (!current.sender_approved && !approves_execution))
        {
            return Err(InstrStop::Revert);
        }

        let payer = context.resolved_target;
        let sender = context.tx.sender;
        let max_cost = context.max_cost;
        if approves_payment {
            let balance_result = self.state.account(&payer, false).map(|account| account.balance());
            let balance = match balance_result {
                Ok(balance) => balance,
                Err(code) => return Err(self.frame_host_error(code)),
            };
            if self.feature(EvmFeatures::BALANCE_CHECK) && balance < max_cost {
                return Err(InstrStop::Revert);
            }
            if !self.feature(EvmFeatures::BALANCE_CHECK) && balance < max_cost {
                let result = self
                    .state
                    .account(&payer, false)
                    .map(|mut account| account.add_balance(max_cost - balance));
                if let Err(code) = result {
                    return Err(self.frame_host_error(code));
                }
            }
            let bump_result =
                self.state.account(&sender, false).map(|mut account| account.bump_nonce());
            let bumped = match bump_result {
                Ok(bumped) => bumped,
                Err(code) => return Err(self.frame_host_error(code)),
            };
            if !bumped {
                return Err(InstrStop::Revert);
            }
            if self.feature(EvmFeatures::FEE_CHARGE) {
                let result = self
                    .state
                    .account(&payer, false)
                    .map(|mut account| account.add_balance(Word::ZERO.wrapping_sub(max_cost)));
                if let Err(code) = result {
                    return Err(self.frame_host_error(code));
                }
            }
        }

        let next = FrameApprovalState {
            payer: if approves_payment { Some(payer) } else { current.payer },
            sender_approved: current.sender_approved || approves_execution,
        };
        let approval = self.frame_approval_stack.last_mut().ok_or(InstrStop::InvalidOpcode)?;
        *approval = next;
        Ok(())
    }

    #[inline]
    fn frame_host_error(&mut self, code: ErrorCode) -> InstrStop {
        self.set_error_code(code);
        InstrStop::FatalExternalError
    }
}
