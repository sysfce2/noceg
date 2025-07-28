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

// Memory protection manager.
class MemoryManager
{
private:

    // Pointer to the memory region being managed.
    void * m_Address { nullptr };

    // Size of the memory region in bytes.
    std::size_t m_Size { 0 };

    // Original protection flags to restore later.
    DWORD m_OldProtection { 0 };

public:

    /**
     * @brief Constructor that changes memory protection for a given region.
     *
     * @param address Pointer to the start of the memory region to protect.
     * @param size Size of the memory region in bytes.
     * @param new_protection New protection flags.
     */
    MemoryManager( void * address, std::size_t size, DWORD new_protection ) noexcept
        : m_Address { address }, m_Size { size }
    {
        if (!VirtualProtect( address, size, new_protection, &m_OldProtection ))
            m_Address = nullptr;
    }

    /**
     * @brief Destructor that restores original memory protection.
     */
    ~MemoryManager() noexcept
    {
        if (m_Address)
            VirtualProtect( m_Address, m_Size, m_OldProtection, &m_OldProtection );
    }

    MemoryManager( const MemoryManager & ) = delete;
    MemoryManager & operator=( const MemoryManager & ) = delete;


    /**
     * @brief Check if the memory manager is in a valid state.
     *
     * @return true if the memory protection change was successful, false otherwise.
     */
    [[nodiscard]] bool IsValid() const noexcept
    {
        return m_Address != nullptr;
    }
};


// Software breakpoint manager.
class BreakpointManager
{
private:

    // Memory address where the breakpoint is set.
    std::uintptr_t m_Address { 0 };

    // Original byte value at the breakpoint address.
    std::uint8_t m_BackupByte { 0 };

    // Flag indicating if a breakpoint is currently active.
    bool m_IsSet { false };

public:


    /**
     * @brief Sets a software breakpoint at the specified memory address.
     *
     * @param address The memory address where to place the breakpoint.
     */
    [[nodiscard]] void SetBreakpoint(
        std::uintptr_t address
    ) noexcept
    {
        if (m_IsSet)
            return;

        auto memory = MemoryManager { reinterpret_cast<void *>(address), 1, PAGE_EXECUTE_READWRITE };
        if (!memory.IsValid())
            return;

        m_Address = address;
        m_BackupByte = *reinterpret_cast<std::uint8_t *>(address);
        *reinterpret_cast<std::uint8_t *>(address) = 0xCC;

        FlushInstructionCache( GetCurrentProcess(), reinterpret_cast<void *>(address), 1 );

        m_IsSet = true;
    }


    // Removes the currently set breakpoint and restores original code.
    [[nodiscard]] void RemoveBreakpoint() noexcept
    {
        if (!m_IsSet)
            return;

        auto memory = MemoryManager { reinterpret_cast<void *>(m_Address), 1, PAGE_EXECUTE_READWRITE };
        if (!memory.IsValid())
            return;

        *reinterpret_cast<std::uint8_t *>(m_Address) = m_BackupByte;
        FlushInstructionCache( GetCurrentProcess(), reinterpret_cast<void *>(m_Address), 1 );

        m_IsSet = false;
    }


    /**
     * @brief Gets the memory address where the breakpoint is set.
     *
     * @return The memory address of the breakpoint, or '0' if no breakpoint is set.
     */
    [[nodiscard]] std::uintptr_t GetAddress() const noexcept
    {
        return m_Address;
    }


    /**
    * @brief Checks if a breakpoint is currently active.
    *
    * @return true if a breakpoint is set, false otherwise.
    */
    [[nodiscard]] bool IsSet() const noexcept
    {
        return m_IsSet;
    }


    /**
     * @brief Destructor that automatically removes any active breakpoint.
     */
    ~BreakpointManager() noexcept
    {
        if (m_IsSet)
            RemoveBreakpoint();
    }
};