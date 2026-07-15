use crate::{
    EvmTypesHost,
    interpreter::{Host, InstrStop, Result, Word, private::GasInstructionCx},
    utils::{b256_to_word, word_to_usize, word_to_usize_saturated},
};
use alloy_primitives::B256;
use evm2_macros::instruction;

#[inline]
fn copy_data<T: EvmTypesHost>(
    cx: &mut GasInstructionCx<'_, '_, '_, T>,
    memory_offset: Word,
    data_offset: Word,
    len: Word,
    data: &[u8],
) -> Result {
    let len = word_to_usize(len)?;
    cx.gas.spend(cx.state.gas_params().copy_cost(len))?;
    if len != 0 {
        let memory_offset = word_to_usize(memory_offset)?;
        cx.state.resize_memory(cx.gas, memory_offset, len)?;
        cx.state.memory().set_data(memory_offset, word_to_usize_saturated(data_offset), len, data);
    }
    Ok(())
}

#[instruction(dynamic_gas)]
pub(crate) fn approve(cx: _, [offset, len, scope]: [Word]) -> Result {
    let len = word_to_usize(*len)?;
    let output = if len == 0 {
        0..0
    } else {
        let offset = word_to_usize(*offset)?;
        let end = offset.checked_add(len).ok_or(InstrStop::MemoryOOG)?;
        if end > u32::MAX as usize {
            return Err(InstrStop::MemoryLimitOOG);
        }
        cx.state.resize_memory(cx.gas, offset, len)?;
        offset as u32..end as u32
    };
    let target = cx.state.message().destination;
    cx.state.host().approve_frame(target, *scope)?;
    cx.state.set_output(output);
    Err(InstrStop::Return)
}

#[instruction]
pub(crate) fn txparam(cx: _, [param]: [Word]) -> Result<out> {
    *out = cx.state.host().frame_tx_param(*param)?;
}

#[instruction]
pub(crate) fn framedataload(cx: _, [offset, frame_index]: [Word]) -> Result<out> {
    let data = cx.state.host().frame_data(*frame_index)?;
    let offset = word_to_usize_saturated(*offset);
    let mut word = B256::ZERO;
    if offset < data.len() {
        let len = 32.min(data.len() - offset);
        word[..len].copy_from_slice(&data[offset..offset + len]);
    }
    *out = b256_to_word(word);
}

#[instruction(dynamic_gas)]
pub(crate) fn framedatacopy(
    cx: _,
    [memory_offset, data_offset, len, frame_index]: [Word],
) -> Result {
    let data = cx.state.host().frame_data(*frame_index)?;
    copy_data(&mut cx, *memory_offset, *data_offset, *len, &data)
}

#[instruction]
pub(crate) fn frameparam(cx: _, [frame_index, param]: [Word]) -> Result<out> {
    *out = cx.state.host().frame_param(*frame_index, *param)?;
}

#[instruction(no_stack_preamble, dynamic_gas)]
pub(crate) fn sigparam(cx: _) -> Result {
    let [signature_index, param] = stack.popn::<2>()?;
    if param == Word::from(4) {
        let [len, data_offset, memory_offset] = stack.popn::<3>()?;
        let data = cx.state.host().frame_signature_bytes(signature_index)?;
        // Metadata SIGPARAM operations have a base cost of 2, while copy mode has the same
        // base cost as CALLDATACOPY (3). The opcode table charges the common 2 upfront.
        cx.gas.spend(1)?;
        return copy_data(&mut cx, memory_offset, data_offset, len, &data);
    }
    let value = cx.state.host().frame_signature_param(signature_index, param)?;
    stack.push(value)
}
