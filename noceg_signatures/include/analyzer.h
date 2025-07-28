/*
 * This software is licensed under the NoCEG Non-Commercial Copyleft License.
 *
 * Copyright (C) 2025 iArtorias <iartorias.re@gmail.com>
 *
 * You may use, copy, modify, and distribute this software non-commercially only.
 * If you distribute binaries or run it as a service, you must also provide
 * the full source code under the same license.
 *
 * This software is provided "as is", without warranty of any kind.
 *
 * Full license text available in LICENSE.md
 */

#pragma once

#include "utils.h"
using namespace CEG;

// Analyzes instructions to identify and categorize CEG protected functions.
class InstructionAnalyzer
{
private:

    ZydisDecoder m_Decoder;

    // Patterns used to identify the finalize CRC function.
    static constexpr std::array<std::string_view, 6> FINALIZE_CRC_PATTERNS =
    {
        "E8 ?? ?? ?? ?? 8D ?? ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B 0D ?? ?? ?? ?? 8B",
        "E8 ?? ?? ?? ?? 8D ?? ?? E8 ?? ?? ?? ?? 8B 0D ?? ?? ?? ?? 8B",
        "E8 ?? ?? ?? ?? 8D ?? ?? ?? E8 ?? ?? ?? ?? 8B 0D ?? ?? ?? ?? 8B",
        "E8 ?? ?? ?? ?? 8D ?? ?? E8 ?? ?? ?? ?? 5F",
        "E8 ?? ?? ?? ?? 8D ?? ?? ?? ?? ?? E8 ?? ?? ?? ?? 5F",
        "E8 ?? ?? ?? ?? 8D ?? ?? ?? E8 ?? ?? ?? ?? 5F",
    };

    // Offset values to append when corresponding patterns are found.
    // Used to set a breakpoint right after the function execution.
    static constexpr std::array<std::uint32_t, 6> FINALIZE_CRC_OFFSETS = { 16, 13, 14, 13, 16, 14 };

private:
    
    /**
    * @brief Processes a single instruction at the given offset.
    *
    * @param data The binary data to analyze.
    * @param address Base address of the data in memory.
    * @param offset Current offset within the data.
    * @param protect_funcs List of known CEG protected function addresses.
    * @return true if instruction was processed successfully, false otherwise.
    */
    bool ProcessInstruction(
        std::span<const std::byte> data,
        const void * address,
        std::uint32_t & offset,
        std::span<const mem::pointer> protect_funcs
    ) noexcept
    {
        ZydisDecodedInstruction instruction;
        ZydisDecodedOperand operands[ZYDIS_MAX_OPERAND_COUNT];

        if (offset + ZYDIS_MAX_INSTRUCTION_LENGTH > data.size())
            return false;

        if (!ZYAN_SUCCESS( ZydisDecoderDecodeFull( &m_Decoder,
            reinterpret_cast<const void *>(data.data() + offset),
            ZYDIS_MAX_INSTRUCTION_LENGTH,
            &instruction,
            operands ) ))
            return false;

        if (IsTargetInstruction( instruction, operands ))
            ProcessTargetInstruction( instruction, operands, address, offset, protect_funcs );

        // Move to the next byte.
        offset += 1;
        return true;
    }
    
    
    /**
    * @brief Determines if an instruction is of interest for the further analysis.
    *
    * @param instruction The decoded instruction.
    * @param operands Array of instruction operands.
    * @return true if the instruction should be analyzed further.
    */
    [[nodiscard]] static bool IsTargetInstruction(
        const ZydisDecodedInstruction & instruction,
        const ZydisDecodedOperand * operands
    ) noexcept
    {
        return (instruction.mnemonic == ZYDIS_MNEMONIC_CALL &&
            operands[0].type == ZYDIS_OPERAND_TYPE_IMMEDIATE) ||
            (instruction.mnemonic == ZYDIS_MNEMONIC_JMP &&
                operands[0].type == ZYDIS_OPERAND_TYPE_IMMEDIATE) ||
            (instruction.mnemonic == ZYDIS_MNEMONIC_MOV &&
                operands[0].type == ZYDIS_OPERAND_TYPE_REGISTER &&
                operands[1].type == ZYDIS_OPERAND_TYPE_IMMEDIATE &&
                operands[0].reg.value == ZYDIS_REGISTER_EAX);
    }
    
    
    /**
    * @brief Processes instructions that match our target.
    *
    * @param instruction The decoded instruction.
    * @param operands Array of instruction operands.
    * @param address Base address of the data in memory.
    * @param offset Current offset within the data.
    * @param protect_funcs List of known CEG protected function addresses.
    */
    void ProcessTargetInstruction(
        const ZydisDecodedInstruction & instruction,
        const ZydisDecodedOperand * operands,
        const void * address,
        std::uint32_t offset,
        std::span<const mem::pointer> protect_funcs
    ) noexcept
    {
        const auto current_address = reinterpret_cast<std::uint32_t>(address) + offset;

        std::uint32_t call_target = 0;

        if (instruction.mnemonic == ZYDIS_MNEMONIC_MOV)
            call_target = VaToOffset( static_cast<std::uint32_t>(operands[1].imm.value.s) );
        else
            call_target = current_address + static_cast<std::uint32_t>(operands[0].imm.value.s + instruction.length);

        auto call_target_ptr = mem::pointer( call_target );

        // Check for the first register thread CEG occurance.
        if ((!Data::CEG_REGISTER_THREAD_FUNC && !Data::CEG_REGISTER_THREAD_FUNC_FUNCS.empty()))
        {
            if (Data::CEG_REGISTER_THREAD_FUNC_FUNCS.contains( call_target_ptr ))
                Data::CEG_REGISTER_THREAD_FUNC = call_target_ptr;
        }

        if (std::ranges::find( protect_funcs, call_target_ptr ) != protect_funcs.end())
            ProcessProtectedFunction( current_address, call_target, address, offset );
    }
    

    /**
    * @brief Analyzes a CEG protected function to determine its type.
    *
    * @param current_address Address of the current instruction.
    * @param target_func Address of the target protected function.
    * @param address Base address of the data in memory.
    * @param call_offset Offset of the call instruction.
    */
    void ProcessProtectedFunction(
        std::uint32_t current_address,
        std::uint32_t target_func,
        const void * address,
        std::uint32_t call_offset
    ) noexcept
    {
        const auto next_instruction_address = current_address + 5;
        const auto * next_instruction_ptr = reinterpret_cast<const std::uint8_t *>(next_instruction_address);

        std::atomic_bool found = false;

        // Pattern match using ranges to find the finalize CRC function.
        for (const auto & [pattern, offset] : std::views::zip( FINALIZE_CRC_PATTERNS, FINALIZE_CRC_OFFSETS ))
        {
            if (auto finalize_crc = FindFunction( pattern,
                reinterpret_cast<const void *>(target_func),
                Data::CEG_SCAN_SIZE );
                finalize_crc.as<std::uint32_t>() != 0)
            {
                // Calculate the breakpoint address using the pattern offset.
                const auto bp = finalize_crc.as<std::uint32_t>() + offset;
                auto func = CalculateRealAddress( address, target_func );
                GetCEGFunctionType( current_address, bp, address, next_instruction_ptr, call_offset, func );

                found.store( true );
                break;
            }
        }

        // Handle even older CEG versions that don't match the patterns.
        if ((Data::CEG_OLD_VERSION && !found.load()))
        {
            // Check for 'call eax' instruction.
            if (*next_instruction_ptr == 0xFF && *(next_instruction_ptr + 1) == 0xD0)
            {
                const auto prev_instruction_address = current_address - 1;
                const auto * prev_instruction_ptr = reinterpret_cast<const std::uint8_t *>(prev_instruction_address);

                auto func = CalculateRealAddress( address, target_func );
                auto eip = CalculateRealAddress( address, current_address - 1 );
                auto bp = CalculateRealAddress( address, next_instruction_address + 2 );

                // Check for 'push ecx' instruction.
                if (*prev_instruction_ptr == 0x51)
                    Data::CEG_PROTECTED_STOLEN_FUNCS_v1.emplace( func, std::make_tuple( func, eip, bp ) );
                else
                    Data::CEG_PROTECTED_STOLEN_FUNCS_v1.emplace( func, std::make_tuple( func, eip + 1, bp ) );
            }
        }
    }


    // Find the protected function prologue by scanning backwards from the call instruction.
    [[nodiscard]] mem::pointer FindFunctionPrologue(
        std::span<const std::byte> data,
        const void * base_address,
        std::uint32_t call_offset
    ) noexcept
    {
        // Start scanning backwards from the call instruction.
        const std::uint32_t start_scan = (call_offset > Data::CEG_SCAN_SIZE) ?
            call_offset - Data::CEG_SCAN_SIZE : 0;

        // Scan backwards looking for the function prologue.
        for (std::uint32_t offset = call_offset; offset > start_scan; --offset)
        {
            ZydisDecodedInstruction instruction;
            ZydisDecodedOperand operands[ZYDIS_MAX_OPERAND_COUNT];

            if (!ZYAN_SUCCESS( ZydisDecoderDecodeFull( &m_Decoder,
                reinterpret_cast<const void *>(data.data() + offset),
                ZYDIS_MAX_INSTRUCTION_LENGTH,
                &instruction,
                operands ) ))
                continue;

            // Look for the function prologue 'push ebp'.
            if (instruction.mnemonic == ZYDIS_MNEMONIC_PUSH &&
                operands[0].type == ZYDIS_OPERAND_TYPE_REGISTER &&
                operands[0].reg.value == ZYDIS_REGISTER_EBP)
            {
                // Check if the next instruction is 'mov ebp, esp'.
                const std::uint32_t next_offset = offset + instruction.length;

                ZydisDecodedInstruction next_instruction;
                ZydisDecodedOperand next_operands[ZYDIS_MAX_OPERAND_COUNT];

                if (ZYAN_SUCCESS( ZydisDecoderDecodeFull( &m_Decoder,
                    reinterpret_cast<const void *>(data.data() + next_offset),
                    ZYDIS_MAX_INSTRUCTION_LENGTH,
                    &next_instruction,
                    next_operands ) ))
                {
                    // Verify this is 'mov ebp, esp'.
                    if (next_instruction.mnemonic == ZYDIS_MNEMONIC_MOV &&
                        next_operands[0].type == ZYDIS_OPERAND_TYPE_REGISTER &&
                        next_operands[1].type == ZYDIS_OPERAND_TYPE_REGISTER &&
                        next_operands[0].reg.value == ZYDIS_REGISTER_EBP &&
                        next_operands[1].reg.value == ZYDIS_REGISTER_ESP)
                    {
                        // Found the function prologue!
                        const auto start = reinterpret_cast<std::uint32_t>(base_address) + offset;
                        return CalculateRealAddress( base_address, start );
                    }
                }
            }
        }

        // Prologue not found.
        return mem::pointer { nullptr };
    }
    
    
    /**
    * Analyzes and categorizes CEG protected functions based on their instruction patterns and CEG version.
    *
    * @param current_address The current memory address.
    * @param bp Address of the breakpoint.
    * @param address Base address of the data in memory.
    * @param next_instruction_ptr Pointer to the next instruction after the current one.
    * @param call_offset Data offset.
    * @param target_func Memory pointer to the target CEG function being analyzed.
    */
    void GetCEGFunctionType(
        std::uint32_t current_address,
        std::uint32_t bp,
        const void * address,
        const std::uint8_t * next_instruction_ptr,
        std::uint32_t call_offset,
        mem::pointer target_func
    ) noexcept
    {
        const auto eip = CalculateRealAddress( address, current_address );
        const auto real_bp = CalculateRealAddress( address, bp );

        if (Data::CEG_OLD_VERSION)
        {
            // Handle old CEG version with 'call eax' instruction.
            if (*next_instruction_ptr == 0xFF && *(next_instruction_ptr + 1) == 0xD0)
            {
                const auto prev_instruction_address = current_address - 1;
                const auto * prev_instruction_ptr = reinterpret_cast<const std::uint8_t *>(prev_instruction_address);

                // Check for 'push ecx' instruction before the current call.
                if (*prev_instruction_ptr == 0x51)
                    Data::CEG_PROTECTED_STOLEN_FUNCS_v1.emplace( target_func, std::make_tuple( target_func, eip - 1, real_bp ) );
                else
                    Data::CEG_PROTECTED_STOLEN_FUNCS_v1.emplace( target_func, std::make_tuple( target_func, eip, real_bp ) );
            }
            // Check for 'jmp eax' instruction.
            else if (*next_instruction_ptr == 0xFF && *(next_instruction_ptr + 1) == 0xE0)
                Data::CEG_PROTECTED_STOLEN_FUNCS_v2.emplace( target_func, std::make_tuple( target_func, eip, real_bp ) );
        }
        else
        {
            const auto * cur_instruction_ptr = reinterpret_cast<const std::uint8_t *>(current_address);

            // Check for 'ret' instruction or 'mov' instruction.
            if (*next_instruction_ptr == 0xC3 || *next_instruction_ptr == 0x89)
                Data::CEG_PROTECTED_CONSTANT_FUNCS.emplace( target_func, std::make_tuple( target_func, eip, real_bp ) );
            // Check for 'jmp eax' instruction.
            else if (*next_instruction_ptr == 0xFF && *(next_instruction_ptr + 1) == 0xE0)
                Data::CEG_PROTECTED_STOLEN_FUNCS_v2.emplace( target_func, std::make_tuple( target_func, eip, real_bp ) );
            // Check if the current instruction is the short jump.
            else if(*cur_instruction_ptr == 0xEB)
                Data::CEG_PROTECTED_CONSTANT_FUNCS.emplace( target_func, std::make_tuple( target_func, eip, real_bp ) );
            else
            {
                // Attempt to find the function prologue.
                const auto * base = reinterpret_cast<const std::byte *>(address);
                std::span<const std::byte> data( base, Data::CEG_SCAN_SIZE );

                auto prologue = FindFunctionPrologue( data, address, call_offset );

                if (prologue)
                    Data::CEG_PROTECTED_STOLEN_FUNCS_v3.emplace( target_func, std::make_tuple( prologue, eip, real_bp ) );
                else
                    Data::CEG_PROTECTED_STOLEN_FUNCS_v3.emplace( target_func, std::make_tuple( target_func, eip, real_bp ) );
            }
        }
    }

public:

    InstructionAnalyzer()
    {
        if (!ZYAN_SUCCESS( ZydisDecoderInit( &m_Decoder,
            ZYDIS_MACHINE_MODE_LONG_COMPAT_32,
            ZYDIS_STACK_WIDTH_32 ) ))
        {
            throw std::runtime_error( "Failed to initialize Zydis decoder." );
        }
    }
    
    
    /**
    * @brief Analyzes binary data to identify CEG protected functions.
     *
     * @param data Binary data to analyze.
     * @param address Base address of the data in memory.
     * @param funcs List of known protected function addresses to look for.
     * @return true if analysis completed successfully, false otherwise.
     */
    [[nodiscard]] bool AnalyzeCEGProtectedFunctions(
        std::span<const std::byte> data,
        const void * address,
        std::span<const mem::pointer> funcs
    ) noexcept
    {
        std::uint32_t offset = 0;
        const auto size = static_cast<std::uint32_t>(data.size());

        while (offset < size)
        {
            if (!ProcessInstruction( data, address, offset, funcs ))
            {
                // If instruction processing fails, move to the next byte.
                offset++;
                continue;
            }
        }

        return true;
    }
};