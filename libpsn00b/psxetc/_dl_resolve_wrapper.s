# PSn00bSDK dynamic linker
# (C) 2021-2022 spicyjpeg - MPL licensed
#
# This function is called by the lazy loader stubs generated by GCC in the
# .plt/.MIPS.stubs section when attempting to call a GOT entry whose address
# hasn't yet been resolved. The generated stubs conform to the MIPS ABI and
# uses the following registers:
# - $t7 = address the resolved function should return to (i.e. $ra of the
#   caller that triggered the stub)
# - $t8 = index of the function in the .dynsym symbol table
# - $t9 = _dl_resolve_wrapper itself's address

.set noreorder

.section .text._dl_resolve_wrapper
.global _dl_resolve_wrapper
.type _dl_resolve_wrapper, @function
_dl_resolve_wrapper:
	# Save the arguments being passed to the function to be resolved.
	addiu $sp, -20
	sw    $a0,  0($sp)
	sw    $a1,  4($sp)
	sw    $a2,  8($sp)
	sw    $a3, 12($sp)
	sw    $t7, 16($sp) # (will be restored directly to $ra)

	# Figure out where the DLL's struct is. dlinit() places a pointer to the
	# struct in the second GOT entry, so it's just a matter of indexing the GOT
	# using $gp. Then call _dl_resolve_helper with the struct and $t8 as
	# arguments, and store the return value into $t0.
	lw    $a0, -0x7fec($gp) # dll = &((uint32_t *) (gp - 0x7ff0))[1]
	move  $a1, $t8

	jal   _dl_resolve_helper
	addiu $sp, -8
	addiu $sp, 8

	# Restore the arguments from the stack and tail-call the function at the
	# address returned by the resolver.
	lw    $a0,  0($sp)
	lw    $a1,  4($sp)
	lw    $a2,  8($sp)
	lw    $a3, 12($sp)
	lw    $ra, 16($sp)

	jr    $v0
	addiu $sp, 20
