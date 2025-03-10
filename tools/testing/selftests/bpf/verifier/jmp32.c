{
	"jset32: BPF_K",
	.insns = {
	BPF_DIRECT_PKT_R2,
	BPF_LDX_MEM(BPF_DW, BPF_REG_7, BPF_REG_2, 0),
	/* reg, high bits shouldn't be tested */
	BPF_JMP32_IMM(BPF_JSET, BPF_REG_7, -2, 1),
	BPF_JMP_IMM(BPF_JA, 0, 0, 1),
	BPF_EXIT_INSN(),

	BPF_JMP32_IMM(BPF_JSET, BPF_REG_7, 1, 1),
	BPF_EXIT_INSN(),
	BPF_MOV64_IMM(BPF_REG_0, 2),
	BPF_EXIT_INSN(),
	},
	.prog_type = BPF_PROG_TYPE_SCHED_CLS,
	.result = ACCEPT,
	.runs = 3,
	.retvals = {
		{ .retval = 0,
		  .data64 = { 1ULL << 63, }
		},
		{ .retval = 2,
		  .data64 = { 1, }
		},
		{ .retval = 2,
		  .data64 = { 1ULL << 63 | 1, }
		},
	},
	.flags = F_NEEDS_EFFICIENT_UNALIGNED_ACCESS,
},
{
	"jset32: BPF_X",
	.insns = {
	BPF_DIRECT_PKT_R2,
	BPF_LDX_MEM(BPF_DW, BPF_REG_7, BPF_REG_2, 0),
	BPF_LD_IMM64(BPF_REG_8, 0x8000000000000000),
	BPF_JMP32_REG(BPF_JSET, BPF_REG_7, BPF_REG_8, 1),
	BPF_JMP_IMM(BPF_JA, 0, 0, 1),
	BPF_EXIT_INSN(),

	BPF_LD_IMM64(BPF_REG_8, 0x8000000000000001),
	BPF_JMP32_REG(BPF_JSET, BPF_REG_7, BPF_REG_8, 1),
	BPF_EXIT_INSN(),
	BPF_MOV64_IMM(BPF_REG_0, 2),
	BPF_EXIT_INSN(),
	},
	.prog_type = BPF_PROG_TYPE_SCHED_CLS,
	.result = ACCEPT,
	.runs = 3,
	.retvals = {
		{ .retval = 0,
		  .data64 = { 1ULL << 63, }
		},
		{ .retval = 2,
		  .data64 = { 1, }
		},
		{ .retval = 2,
		  .data64 = { 1ULL << 63 | 1, }
		},
	},
	.flags = F_NEEDS_EFFICIENT_UNALIGNED_ACCESS,
},
{
	"jset32: ignores upper bits",
	.insns = {
	BPF_MOV64_IMM(BPF_REG_0, 0),
	BPF_LD_IMM64(BPF_REG_7, 0x8000000000000000),
	BPF_LD_IMM64(BPF_REG_8, 0x8000000000000000),
	BPF_JMP_REG(BPF_JSET, BPF_REG_7, BPF_REG_8, 1),
	BPF_EXIT_INSN(),
	BPF_JMP32_REG(BPF_JSET, BPF_REG_7, BPF_REG_8, 1),
	BPF_MOV64_IMM(BPF_REG_0, 2),
	BPF_EXIT_INSN(),
	},
	.result = ACCEPT,
	.retval = 2,
},
{
	"jset32: min/max deduction",
	.insns = {
	BPF_RAND_UEXT_R7,
	BPF_MOV64_IMM(BPF_REG_0, 0),
	BPF_JMP32_IMM(BPF_JSET, BPF_REG_7, 0x10, 1),
	BPF_EXIT_INSN(),
	BPF_JMP32_IMM(BPF_JGE, BPF_REG_7, 0x10, 1),
	/* unpriv: nospec (inserted to prevent "R9 !read_ok") */
	BPF_LDX_MEM(BPF_B, BPF_REG_8, BPF_REG_9, 0),
	BPF_EXIT_INSN(),
	},
	.result = ACCEPT,
},
{
	"jeq32: BPF_K",
	.insns = {
	BPF_DIRECT_PKT_R2,
	BPF_LDX_MEM(BPF_DW, BPF_REG_7, BPF_REG_2, 0),
	BPF_JMP32_IMM(BPF_JEQ, BPF_REG_7, -1, 1),
	BPF_EXIT_INSN(),
	BPF_MOV64_IMM(BPF_REG_0, 2),
	BPF_EXIT_INSN(),
	},
	.prog_type = BPF_PROG_TYPE_SCHED_CLS,
	.result = ACCEPT,
	.runs = 2,
	.retvals = {
		{ .retval = 0,
		  .data64 = { -2, }
		},
		{ .retval = 2,
		  .data64 = { -1, }
		},
	},
	.flags = F_NEEDS_EFFICIENT_UNALIGNED_ACCESS,
},
{
	"jeq32: BPF_X",
	.insns = {
	BPF_DIRECT_PKT_R2,
	BPF_LDX_MEM(BPF_DW, BPF_REG_7, BPF_REG_2, 0),
	BPF_LD_IMM64(BPF_REG_8, 0x7000000000000001),
	BPF_JMP32_REG(BPF_JEQ, BPF_REG_7, BPF_REG_8, 1),
	BPF_EXIT_INSN(),
	BPF_MOV64_IMM(BPF_REG_0, 2),
	BPF_EXIT_INSN(),
	},
	.prog_type = BPF_PROG_TYPE_SCHED_CLS,
	.result = ACCEPT,
	.runs = 3,
	.retvals = {
		{ .retval = 0,
		  .data64 = { 2, }
		},
		{ .retval = 2,
		  .data64 = { 1, }
		},
		{ .retval = 2,
		  .data64 = { 1ULL << 63 | 1, }
		},
	},
	.flags = F_NEEDS_EFFICIENT_UNALIGNED_ACCESS,
},
{
	"jeq32: min/max deduction",
	.insns = {
	BPF_RAND_UEXT_R7,
	BPF_MOV64_IMM(BPF_REG_0, 0),
	BPF_JMP32_IMM(BPF_JEQ, BPF_REG_7, 0x10, 1),
	BPF_EXIT_INSN(),
	BPF_JMP32_IMM(BPF_JSGE, BPF_REG_7, 0xf, 1),
	/* unpriv: nospec (inserted to prevent "R9 !read_ok") */
	BPF_LDX_MEM(BPF_B, BPF_REG_8, BPF_REG_9, 0),
	BPF_EXIT_INSN(),
	},
	.result = ACCEPT,
},
{
	"jne32: BPF_K",
	.insns = {
	BPF_DIRECT_PKT_R2,
	BPF_LDX_MEM(BPF_DW, BPF_REG_7, BPF_REG_2, 0),
	BPF_JMP32_IMM(BPF_JNE, BPF_REG_7, -1, 1),
	BPF_EXIT_INSN(),
	BPF_MOV64_IMM(BPF_REG_0, 2),
	BPF_EXIT_INSN(),
	},
	.prog_type = BPF_PROG_TYPE_SCHED_CLS,
	.result = ACCEPT,
	.runs = 2,
	.retvals = {
		{ .retval = 2,
		  .data64 = { 1, }
		},
		{ .retval = 0,
		  .data64 = { -1, }
		},
	},
	.flags = F_NEEDS_EFFICIENT_UNALIGNED_ACCESS,
},
{
	"jne32: BPF_X",
	.insns = {
	BPF_DIRECT_PKT_R2,
	BPF_LDX_MEM(BPF_DW, BPF_REG_7, BPF_REG_2, 0),
	BPF_LD_IMM64(BPF_REG_8, 0x8000000000000001),
	BPF_JMP32_REG(BPF_JNE, BPF_REG_7, BPF_REG_8, 1),
	BPF_EXIT_INSN(),
	BPF_MOV64_IMM(BPF_REG_0, 2),
	BPF_EXIT_INSN(),
	},
	.prog_type = BPF_PROG_TYPE_SCHED_CLS,
	.result = ACCEPT,
	.runs = 3,
	.retvals = {
		{ .retval = 0,
		  .data64 = { 1, }
		},
		{ .retval = 2,
		  .data64 = { 2, }
		},
		{ .retval = 2,
		  .data64 = { 1ULL << 63 | 2, }
		},
	},
	.flags = F_NEEDS_EFFICIENT_UNALIGNED_ACCESS,
},
{
	"jne32: min/max deduction",
	.insns = {
	BPF_RAND_UEXT_R7,
	BPF_MOV64_IMM(BPF_REG_0, 0),
	BPF_JMP32_IMM(BPF_JNE, BPF_REG_7, 0x10, 1),
	BPF_JMP_IMM(BPF_JNE, BPF_REG_7, 0x10, 1),
	BPF_EXIT_INSN(),
	/* unpriv: nospec (inserted to prevent "R9 !read_ok") */
	BPF_LDX_MEM(BPF_B, BPF_REG_8, BPF_REG_9, 0),
	BPF_EXIT_INSN(),
	},
	.result = ACCEPT,
},
{
	"jge32: BPF_K",
	.insns = {
	BPF_DIRECT_PKT_R2,
	BPF_LDX_MEM(BPF_DW, BPF_REG_7, BPF_REG_2, 0),
	BPF_JMP32_IMM(BPF_JGE, BPF_REG_7, UINT_MAX - 1, 1),
	BPF_EXIT_INSN(),
	BPF_ALU32_IMM(BPF_MOV, BPF_REG_0, 2),
	BPF_EXIT_INSN(),
	},
	.prog_type = BPF_PROG_TYPE_SCHED_CLS,
	.result = ACCEPT,
	.runs = 3,
	.retvals = {
		{ .retval = 2,
		  .data64 = { UINT_MAX, }
		},
		{ .retval = 2,
		  .data64 = { UINT_MAX - 1, }
		},
		{ .retval = 0,
		  .data64 = { 0, }
		},
	},
	.flags = F_NEEDS_EFFICIENT_UNALIGNED_ACCESS,
},
{
	"jge32: BPF_X",
	.insns = {
	BPF_DIRECT_PKT_R2,
	BPF_LD_IMM64(BPF_REG_8, UINT_MAX | 1ULL << 32),
	BPF_LDX_MEM(BPF_DW, BPF_REG_7, BPF_REG_2, 0),
	BPF_JMP32_REG(BPF_JGE, BPF_REG_7, BPF_REG_8, 1),
	BPF_EXIT_INSN(),
	BPF_ALU32_IMM(BPF_MOV, BPF_REG_0, 2),
	BPF_EXIT_INSN(),
	},
	.prog_type = BPF_PROG_TYPE_SCHED_CLS,
	.result = ACCEPT,
	.runs = 3,
	.retvals = {
		{ .retval = 2,
		  .data64 = { UINT_MAX, }
		},
		{ .retval = 0,
		  .data64 = { INT_MAX, }
		},
		{ .retval = 0,
		  .data64 = { (UINT_MAX - 1) | 2ULL << 32, }
		},
	},
	.flags = F_NEEDS_EFFICIENT_UNALIGNED_ACCESS,
},
{
	"jge32: min/max deduction",
	.insns = {
	BPF_RAND_UEXT_R7,
	BPF_ALU32_IMM(BPF_MOV, BPF_REG_0, 2),
	BPF_LD_IMM64(BPF_REG_8, 0x7ffffff0 | 1ULL << 32),
	BPF_JMP32_REG(BPF_JGE, BPF_REG_7, BPF_REG_8, 1),
	BPF_EXIT_INSN(),
	BPF_JMP32_IMM(BPF_JGE, BPF_REG_7, 0x7ffffff0, 1),
	/* unpriv: nospec (inserted to prevent "R0 invalid mem access 'scalar'") */
	BPF_LDX_MEM(BPF_DW, BPF_REG_0, BPF_REG_0, 0),
	BPF_EXIT_INSN(),
	},
	.result = ACCEPT,
	.retval = 2,
	.flags = F_NEEDS_EFFICIENT_UNALIGNED_ACCESS,
},
{
	"jgt32: BPF_K",
	.insns = {
	BPF_DIRECT_PKT_R2,
	BPF_LDX_MEM(BPF_DW, BPF_REG_7, BPF_REG_2, 0),
	BPF_JMP32_IMM(BPF_JGT, BPF_REG_7, UINT_MAX - 1, 1),
	BPF_EXIT_INSN(),
	BPF_ALU32_IMM(BPF_MOV, BPF_REG_0, 2),
	BPF_EXIT_INSN(),
	},
	.prog_type = BPF_PROG_TYPE_SCHED_CLS,
	.result = ACCEPT,
	.runs = 3,
	.retvals = {
		{ .retval = 2,
		  .data64 = { UINT_MAX, }
		},
		{ .retval = 0,
		  .data64 = { UINT_MAX - 1, }
		},
		{ .retval = 0,
		  .data64 = { 0, }
		},
	},
	.flags = F_NEEDS_EFFICIENT_UNALIGNED_ACCESS,
},
{
	"jgt32: BPF_X",
	.insns = {
	BPF_DIRECT_PKT_R2,
	BPF_LD_IMM64(BPF_REG_8, (UINT_MAX - 1) | 1ULL << 32),
	BPF_LDX_MEM(BPF_DW, BPF_REG_7, BPF_REG_2, 0),
	BPF_JMP32_REG(BPF_JGT, BPF_REG_7, BPF_REG_8, 1),
	BPF_EXIT_INSN(),
	BPF_ALU32_IMM(BPF_MOV, BPF_REG_0, 2),
	BPF_EXIT_INSN(),
	},
	.prog_type = BPF_PROG_TYPE_SCHED_CLS,
	.result = ACCEPT,
	.runs = 3,
	.retvals = {
		{ .retval = 2,
		  .data64 = { UINT_MAX, }
		},
		{ .retval = 0,
		  .data64 = { UINT_MAX - 1, }
		},
		{ .retval = 0,
		  .data64 = { (UINT_MAX - 1) | 2ULL << 32, }
		},
	},
	.flags = F_NEEDS_EFFICIENT_UNALIGNED_ACCESS,
},
{
	"jgt32: min/max deduction",
	.insns = {
	BPF_RAND_UEXT_R7,
	BPF_ALU32_IMM(BPF_MOV, BPF_REG_0, 2),
	BPF_LD_IMM64(BPF_REG_8, 0x7ffffff0 | 1ULL << 32),
	BPF_JMP32_REG(BPF_JGT, BPF_REG_7, BPF_REG_8, 1),
	BPF_EXIT_INSN(),
	BPF_JMP_IMM(BPF_JGT, BPF_REG_7, 0x7ffffff0, 1),
	/* unpriv: nospec (inserted to prevent "R0 invalid mem access 'scalar'") */
	BPF_LDX_MEM(BPF_DW, BPF_REG_0, BPF_REG_0, 0),
	BPF_EXIT_INSN(),
	},
	.result = ACCEPT,
	.retval = 2,
	.flags = F_NEEDS_EFFICIENT_UNALIGNED_ACCESS,
},
{
	"jle32: BPF_K",
	.insns = {
	BPF_DIRECT_PKT_R2,
	BPF_LDX_MEM(BPF_DW, BPF_REG_7, BPF_REG_2, 0),
	BPF_JMP32_IMM(BPF_JLE, BPF_REG_7, INT_MAX, 1),
	BPF_EXIT_INSN(),
	BPF_ALU32_IMM(BPF_MOV, BPF_REG_0, 2),
	BPF_EXIT_INSN(),
	},
	.prog_type = BPF_PROG_TYPE_SCHED_CLS,
	.result = ACCEPT,
	.runs = 3,
	.retvals = {
		{ .retval = 2,
		  .data64 = { INT_MAX - 1, }
		},
		{ .retval = 0,
		  .data64 = { UINT_MAX, }
		},
		{ .retval = 2,
		  .data64 = { INT_MAX, }
		},
	},
	.flags = F_NEEDS_EFFICIENT_UNALIGNED_ACCESS,
},
{
	"jle32: BPF_X",
	.insns = {
	BPF_DIRECT_PKT_R2,
	BPF_LD_IMM64(BPF_REG_8, (INT_MAX - 1) | 2ULL << 32),
	BPF_LDX_MEM(BPF_DW, BPF_REG_7, BPF_REG_2, 0),
	BPF_JMP32_REG(BPF_JLE, BPF_REG_7, BPF_REG_8, 1),
	BPF_EXIT_INSN(),
	BPF_ALU32_IMM(BPF_MOV, BPF_REG_0, 2),
	BPF_EXIT_INSN(),
	},
	.prog_type = BPF_PROG_TYPE_SCHED_CLS,
	.result = ACCEPT,
	.runs = 3,
	.retvals = {
		{ .retval = 0,
		  .data64 = { INT_MAX | 1ULL << 32, }
		},
		{ .retval = 2,
		  .data64 = { INT_MAX - 2, }
		},
		{ .retval = 0,
		  .data64 = { UINT_MAX, }
		},
	},
	.flags = F_NEEDS_EFFICIENT_UNALIGNED_ACCESS,
},
{
	"jle32: min/max deduction",
	.insns = {
	BPF_RAND_UEXT_R7,
	BPF_ALU32_IMM(BPF_MOV, BPF_REG_0, 2),
	BPF_LD_IMM64(BPF_REG_8, 0x7ffffff0 | 1ULL << 32),
	BPF_JMP32_REG(BPF_JLE, BPF_REG_7, BPF_REG_8, 1),
	BPF_EXIT_INSN(),
	BPF_JMP32_IMM(BPF_JLE, BPF_REG_7, 0x7ffffff0, 1),
	/* unpriv: nospec (inserted to prevent "R0 invalid mem access 'scalar'") */
	BPF_LDX_MEM(BPF_DW, BPF_REG_0, BPF_REG_0, 0),
	BPF_EXIT_INSN(),
	},
	.result = ACCEPT,
	.retval = 2,
	.flags = F_NEEDS_EFFICIENT_UNALIGNED_ACCESS,
},
{
	"jlt32: BPF_K",
	.insns = {
	BPF_DIRECT_PKT_R2,
	BPF_LDX_MEM(BPF_DW, BPF_REG_7, BPF_REG_2, 0),
	BPF_JMP32_IMM(BPF_JLT, BPF_REG_7, INT_MAX, 1),
	BPF_EXIT_INSN(),
	BPF_ALU32_IMM(BPF_MOV, BPF_REG_0, 2),
	BPF_EXIT_INSN(),
	},
	.prog_type = BPF_PROG_TYPE_SCHED_CLS,
	.result = ACCEPT,
	.runs = 3,
	.retvals = {
		{ .retval = 0,
		  .data64 = { INT_MAX, }
		},
		{ .retval = 0,
		  .data64 = { UINT_MAX, }
		},
		{ .retval = 2,
		  .data64 = { INT_MAX - 1, }
		},
	},
	.flags = F_NEEDS_EFFICIENT_UNALIGNED_ACCESS,
},
{
	"jlt32: BPF_X",
	.insns = {
	BPF_DIRECT_PKT_R2,
	BPF_LD_IMM64(BPF_REG_8, INT_MAX | 2ULL << 32),
	BPF_LDX_MEM(BPF_DW, BPF_REG_7, BPF_REG_2, 0),
	BPF_JMP32_REG(BPF_JLT, BPF_REG_7, BPF_REG_8, 1),
	BPF_EXIT_INSN(),
	BPF_ALU32_IMM(BPF_MOV, BPF_REG_0, 2),
	BPF_EXIT_INSN(),
	},
	.prog_type = BPF_PROG_TYPE_SCHED_CLS,
	.result = ACCEPT,
	.runs = 3,
	.retvals = {
		{ .retval = 0,
		  .data64 = { INT_MAX | 1ULL << 32, }
		},
		{ .retval = 0,
		  .data64 = { UINT_MAX, }
		},
		{ .retval = 2,
		  .data64 = { (INT_MAX - 1) | 3ULL << 32, }
		},
	},
	.flags = F_NEEDS_EFFICIENT_UNALIGNED_ACCESS,
},
{
	"jlt32: min/max deduction",
	.insns = {
	BPF_RAND_UEXT_R7,
	BPF_ALU32_IMM(BPF_MOV, BPF_REG_0, 2),
	BPF_LD_IMM64(BPF_REG_8, 0x7ffffff0 | 1ULL << 32),
	BPF_JMP32_REG(BPF_JLT, BPF_REG_7, BPF_REG_8, 1),
	BPF_EXIT_INSN(),
	BPF_JMP_IMM(BPF_JSLT, BPF_REG_7, 0x7ffffff0, 1),
	/* unpriv: nospec (inserted to prevent "R0 invalid mem access 'scalar'") */
	BPF_LDX_MEM(BPF_DW, BPF_REG_0, BPF_REG_0, 0),
	BPF_EXIT_INSN(),
	},
	.result = ACCEPT,
	.retval = 2,
	.flags = F_NEEDS_EFFICIENT_UNALIGNED_ACCESS,
},
{
	"jsge32: BPF_K",
	.insns = {
	BPF_DIRECT_PKT_R2,
	BPF_LDX_MEM(BPF_DW, BPF_REG_7, BPF_REG_2, 0),
	BPF_JMP32_IMM(BPF_JSGE, BPF_REG_7, -1, 1),
	BPF_EXIT_INSN(),
	BPF_ALU32_IMM(BPF_MOV, BPF_REG_0, 2),
	BPF_EXIT_INSN(),
	},
	.prog_type = BPF_PROG_TYPE_SCHED_CLS,
	.result = ACCEPT,
	.runs = 3,
	.retvals = {
		{ .retval = 2,
		  .data64 = { 0, }
		},
		{ .retval = 2,
		  .data64 = { -1, }
		},
		{ .retval = 0,
		  .data64 = { -2, }
		},
	},
	.flags = F_NEEDS_EFFICIENT_UNALIGNED_ACCESS,
},
{
	"jsge32: BPF_X",
	.insns = {
	BPF_DIRECT_PKT_R2,
	BPF_LD_IMM64(BPF_REG_8, (__u32)-1 | 2ULL << 32),
	BPF_LDX_MEM(BPF_DW, BPF_REG_7, BPF_REG_2, 0),
	BPF_JMP32_REG(BPF_JSGE, BPF_REG_7, BPF_REG_8, 1),
	BPF_EXIT_INSN(),
	BPF_ALU32_IMM(BPF_MOV, BPF_REG_0, 2),
	BPF_EXIT_INSN(),
	},
	.prog_type = BPF_PROG_TYPE_SCHED_CLS,
	.result = ACCEPT,
	.runs = 3,
	.retvals = {
		{ .retval = 2,
		  .data64 = { -1, }
		},
		{ .retval = 2,
		  .data64 = { 0x7fffffff | 1ULL << 32, }
		},
		{ .retval = 0,
		  .data64 = { -2, }
		},
	},
	.flags = F_NEEDS_EFFICIENT_UNALIGNED_ACCESS,
},
{
	"jsge32: min/max deduction",
	.insns = {
	BPF_RAND_UEXT_R7,
	BPF_ALU32_IMM(BPF_MOV, BPF_REG_0, 2),
	BPF_LD_IMM64(BPF_REG_8, 0x7ffffff0 | 1ULL << 32),
	BPF_JMP32_REG(BPF_JSGE, BPF_REG_7, BPF_REG_8, 1),
	BPF_EXIT_INSN(),
	BPF_JMP_IMM(BPF_JSGE, BPF_REG_7, 0x7ffffff0, 1),
	/* unpriv: nospec (inserted to prevent "R0 invalid mem access 'scalar'") */
	BPF_LDX_MEM(BPF_DW, BPF_REG_0, BPF_REG_0, 0),
	BPF_EXIT_INSN(),
	},
	.result = ACCEPT,
	.retval = 2,
	.flags = F_NEEDS_EFFICIENT_UNALIGNED_ACCESS,
},
{
	"jsgt32: BPF_K",
	.insns = {
	BPF_DIRECT_PKT_R2,
	BPF_LDX_MEM(BPF_DW, BPF_REG_7, BPF_REG_2, 0),
	BPF_JMP32_IMM(BPF_JSGT, BPF_REG_7, -1, 1),
	BPF_EXIT_INSN(),
	BPF_ALU32_IMM(BPF_MOV, BPF_REG_0, 2),
	BPF_EXIT_INSN(),
	},
	.prog_type = BPF_PROG_TYPE_SCHED_CLS,
	.result = ACCEPT,
	.runs = 3,
	.retvals = {
		{ .retval = 0,
		  .data64 = { (__u32)-2, }
		},
		{ .retval = 0,
		  .data64 = { -1, }
		},
		{ .retval = 2,
		  .data64 = { 1, }
		},
	},
	.flags = F_NEEDS_EFFICIENT_UNALIGNED_ACCESS,
},
{
	"jsgt32: BPF_X",
	.insns = {
	BPF_DIRECT_PKT_R2,
	BPF_LD_IMM64(BPF_REG_8, 0x7ffffffe | 1ULL << 32),
	BPF_LDX_MEM(BPF_DW, BPF_REG_7, BPF_REG_2, 0),
	BPF_JMP32_REG(BPF_JSGT, BPF_REG_7, BPF_REG_8, 1),
	BPF_EXIT_INSN(),
	BPF_ALU32_IMM(BPF_MOV, BPF_REG_0, 2),
	BPF_EXIT_INSN(),
	},
	.prog_type = BPF_PROG_TYPE_SCHED_CLS,
	.result = ACCEPT,
	.runs = 3,
	.retvals = {
		{ .retval = 0,
		  .data64 = { 0x7ffffffe, }
		},
		{ .retval = 0,
		  .data64 = { 0x1ffffffffULL, }
		},
		{ .retval = 2,
		  .data64 = { 0x7fffffff, }
		},
	},
	.flags = F_NEEDS_EFFICIENT_UNALIGNED_ACCESS,
},
{
	"jsgt32: min/max deduction",
	.insns = {
	BPF_RAND_SEXT_R7,
	BPF_ALU32_IMM(BPF_MOV, BPF_REG_0, 2),
	BPF_LD_IMM64(BPF_REG_8, (__u32)(-2) | 1ULL << 32),
	BPF_JMP32_REG(BPF_JSGT, BPF_REG_7, BPF_REG_8, 1),
	BPF_EXIT_INSN(),
	BPF_JMP_IMM(BPF_JSGT, BPF_REG_7, -2, 1),
	/* unpriv: nospec (inserted to prevent "R0 invalid mem access 'scalar'") */
	BPF_LDX_MEM(BPF_DW, BPF_REG_0, BPF_REG_0, 0),
	BPF_EXIT_INSN(),
	},
	.result = ACCEPT,
	.retval = 2,
	.flags = F_NEEDS_EFFICIENT_UNALIGNED_ACCESS,
},
{
	"jsle32: BPF_K",
	.insns = {
	BPF_DIRECT_PKT_R2,
	BPF_LDX_MEM(BPF_DW, BPF_REG_7, BPF_REG_2, 0),
	BPF_JMP32_IMM(BPF_JSLE, BPF_REG_7, -1, 1),
	BPF_EXIT_INSN(),
	BPF_ALU32_IMM(BPF_MOV, BPF_REG_0, 2),
	BPF_EXIT_INSN(),
	},
	.prog_type = BPF_PROG_TYPE_SCHED_CLS,
	.result = ACCEPT,
	.runs = 3,
	.retvals = {
		{ .retval = 2,
		  .data64 = { (__u32)-2, }
		},
		{ .retval = 2,
		  .data64 = { -1, }
		},
		{ .retval = 0,
		  .data64 = { 1, }
		},
	},
	.flags = F_NEEDS_EFFICIENT_UNALIGNED_ACCESS,
},
{
	"jsle32: BPF_X",
	.insns = {
	BPF_DIRECT_PKT_R2,
	BPF_LD_IMM64(BPF_REG_8, 0x7ffffffe | 1ULL << 32),
	BPF_LDX_MEM(BPF_DW, BPF_REG_7, BPF_REG_2, 0),
	BPF_JMP32_REG(BPF_JSLE, BPF_REG_7, BPF_REG_8, 1),
	BPF_EXIT_INSN(),
	BPF_ALU32_IMM(BPF_MOV, BPF_REG_0, 2),
	BPF_EXIT_INSN(),
	},
	.prog_type = BPF_PROG_TYPE_SCHED_CLS,
	.result = ACCEPT,
	.runs = 3,
	.retvals = {
		{ .retval = 2,
		  .data64 = { 0x7ffffffe, }
		},
		{ .retval = 2,
		  .data64 = { (__u32)-1, }
		},
		{ .retval = 0,
		  .data64 = { 0x7fffffff | 2ULL << 32, }
		},
	},
	.flags = F_NEEDS_EFFICIENT_UNALIGNED_ACCESS,
},
{
	"jsle32: min/max deduction",
	.insns = {
	BPF_RAND_UEXT_R7,
	BPF_ALU32_IMM(BPF_MOV, BPF_REG_0, 2),
	BPF_LD_IMM64(BPF_REG_8, 0x7ffffff0 | 1ULL << 32),
	BPF_JMP32_REG(BPF_JSLE, BPF_REG_7, BPF_REG_8, 1),
	BPF_EXIT_INSN(),
	BPF_JMP_IMM(BPF_JSLE, BPF_REG_7, 0x7ffffff0, 1),
	/* unpriv: nospec (inserted to prevent "R0 invalid mem access 'scalar'") */
	BPF_LDX_MEM(BPF_DW, BPF_REG_0, BPF_REG_0, 0),
	BPF_EXIT_INSN(),
	},
	.result = ACCEPT,
	.retval = 2,
	.flags = F_NEEDS_EFFICIENT_UNALIGNED_ACCESS,
},
{
	"jslt32: BPF_K",
	.insns = {
	BPF_DIRECT_PKT_R2,
	BPF_LDX_MEM(BPF_DW, BPF_REG_7, BPF_REG_2, 0),
	BPF_JMP32_IMM(BPF_JSLT, BPF_REG_7, -1, 1),
	BPF_EXIT_INSN(),
	BPF_ALU32_IMM(BPF_MOV, BPF_REG_0, 2),
	BPF_EXIT_INSN(),
	},
	.prog_type = BPF_PROG_TYPE_SCHED_CLS,
	.result = ACCEPT,
	.runs = 3,
	.retvals = {
		{ .retval = 2,
		  .data64 = { (__u32)-2, }
		},
		{ .retval = 0,
		  .data64 = { -1, }
		},
		{ .retval = 0,
		  .data64 = { 1, }
		},
	},
	.flags = F_NEEDS_EFFICIENT_UNALIGNED_ACCESS,
},
{
	"jslt32: BPF_X",
	.insns = {
	BPF_DIRECT_PKT_R2,
	BPF_LD_IMM64(BPF_REG_8, 0x7fffffff | 1ULL << 32),
	BPF_LDX_MEM(BPF_DW, BPF_REG_7, BPF_REG_2, 0),
	BPF_JMP32_REG(BPF_JSLT, BPF_REG_7, BPF_REG_8, 1),
	BPF_EXIT_INSN(),
	BPF_ALU32_IMM(BPF_MOV, BPF_REG_0, 2),
	BPF_EXIT_INSN(),
	},
	.prog_type = BPF_PROG_TYPE_SCHED_CLS,
	.result = ACCEPT,
	.runs = 3,
	.retvals = {
		{ .retval = 2,
		  .data64 = { 0x7ffffffe, }
		},
		{ .retval = 2,
		  .data64 = { 0xffffffff, }
		},
		{ .retval = 0,
		  .data64 = { 0x7fffffff | 2ULL << 32, }
		},
	},
	.flags = F_NEEDS_EFFICIENT_UNALIGNED_ACCESS,
},
{
	"jslt32: min/max deduction",
	.insns = {
	BPF_RAND_SEXT_R7,
	BPF_ALU32_IMM(BPF_MOV, BPF_REG_0, 2),
	BPF_LD_IMM64(BPF_REG_8, (__u32)(-1) | 1ULL << 32),
	BPF_JMP32_REG(BPF_JSLT, BPF_REG_7, BPF_REG_8, 1),
	BPF_EXIT_INSN(),
	BPF_JMP32_IMM(BPF_JSLT, BPF_REG_7, -1, 1),
	/* unpriv: nospec (inserted to prevent "R0 invalid mem access 'scalar'") */
	BPF_LDX_MEM(BPF_DW, BPF_REG_0, BPF_REG_0, 0),
	BPF_EXIT_INSN(),
	},
	.result = ACCEPT,
	.retval = 2,
	.flags = F_NEEDS_EFFICIENT_UNALIGNED_ACCESS,
},
{
	"jgt32: range bound deduction, reg op imm",
	.insns = {
	BPF_ST_MEM(BPF_DW, BPF_REG_10, -8, 0),
	BPF_MOV64_REG(BPF_REG_8, BPF_REG_1),
	BPF_MOV64_REG(BPF_REG_2, BPF_REG_10),
	BPF_ALU64_IMM(BPF_ADD, BPF_REG_2, -8),
	BPF_LD_MAP_FD(BPF_REG_1, 0),
	BPF_RAW_INSN(BPF_JMP | BPF_CALL, 0, 0, 0, BPF_FUNC_map_lookup_elem),
	BPF_JMP_IMM(BPF_JEQ, BPF_REG_0, 0, 9),
	BPF_MOV64_REG(BPF_REG_1, BPF_REG_8),
	BPF_MOV64_REG(BPF_REG_8, BPF_REG_0),
	BPF_EMIT_CALL(BPF_FUNC_get_cgroup_classid),
	BPF_JMP32_IMM(BPF_JGT, BPF_REG_0, 1, 5),
	BPF_MOV32_REG(BPF_REG_6, BPF_REG_0),
	BPF_ALU64_IMM(BPF_LSH, BPF_REG_6, 32),
	BPF_ALU64_IMM(BPF_RSH, BPF_REG_6, 32),
	BPF_ALU64_REG(BPF_ADD, BPF_REG_8, BPF_REG_6),
	BPF_ST_MEM(BPF_B, BPF_REG_8, 0, 0),
	BPF_MOV32_IMM(BPF_REG_0, 0),
	BPF_EXIT_INSN(),
	},
	.prog_type = BPF_PROG_TYPE_SCHED_CLS,
	.fixup_map_hash_48b = { 4 },
	.result = ACCEPT,
	.flags = F_NEEDS_EFFICIENT_UNALIGNED_ACCESS,
},
{
	"jgt32: range bound deduction, reg1 op reg2, reg1 unknown",
	.insns = {
	BPF_ST_MEM(BPF_DW, BPF_REG_10, -8, 0),
	BPF_MOV64_REG(BPF_REG_8, BPF_REG_1),
	BPF_MOV64_REG(BPF_REG_2, BPF_REG_10),
	BPF_ALU64_IMM(BPF_ADD, BPF_REG_2, -8),
	BPF_LD_MAP_FD(BPF_REG_1, 0),
	BPF_RAW_INSN(BPF_JMP | BPF_CALL, 0, 0, 0, BPF_FUNC_map_lookup_elem),
	BPF_JMP_IMM(BPF_JEQ, BPF_REG_0, 0, 10),
	BPF_MOV64_REG(BPF_REG_1, BPF_REG_8),
	BPF_MOV64_REG(BPF_REG_8, BPF_REG_0),
	BPF_EMIT_CALL(BPF_FUNC_get_cgroup_classid),
	BPF_MOV32_IMM(BPF_REG_2, 1),
	BPF_JMP32_REG(BPF_JGT, BPF_REG_0, BPF_REG_2, 5),
	BPF_MOV32_REG(BPF_REG_6, BPF_REG_0),
	BPF_ALU64_IMM(BPF_LSH, BPF_REG_6, 32),
	BPF_ALU64_IMM(BPF_RSH, BPF_REG_6, 32),
	BPF_ALU64_REG(BPF_ADD, BPF_REG_8, BPF_REG_6),
	BPF_ST_MEM(BPF_B, BPF_REG_8, 0, 0),
	BPF_MOV32_IMM(BPF_REG_0, 0),
	BPF_EXIT_INSN(),
	},
	.prog_type = BPF_PROG_TYPE_SCHED_CLS,
	.fixup_map_hash_48b = { 4 },
	.result = ACCEPT,
	.flags = F_NEEDS_EFFICIENT_UNALIGNED_ACCESS,
},
{
	"jle32: range bound deduction, reg1 op reg2, reg2 unknown",
	.insns = {
	BPF_ST_MEM(BPF_DW, BPF_REG_10, -8, 0),
	BPF_MOV64_REG(BPF_REG_8, BPF_REG_1),
	BPF_MOV64_REG(BPF_REG_2, BPF_REG_10),
	BPF_ALU64_IMM(BPF_ADD, BPF_REG_2, -8),
	BPF_LD_MAP_FD(BPF_REG_1, 0),
	BPF_RAW_INSN(BPF_JMP | BPF_CALL, 0, 0, 0, BPF_FUNC_map_lookup_elem),
	BPF_JMP_IMM(BPF_JEQ, BPF_REG_0, 0, 10),
	BPF_MOV64_REG(BPF_REG_1, BPF_REG_8),
	BPF_MOV64_REG(BPF_REG_8, BPF_REG_0),
	BPF_EMIT_CALL(BPF_FUNC_get_cgroup_classid),
	BPF_MOV32_IMM(BPF_REG_2, 1),
	BPF_JMP32_REG(BPF_JLE, BPF_REG_2, BPF_REG_0, 5),
	BPF_MOV32_REG(BPF_REG_6, BPF_REG_0),
	BPF_ALU64_IMM(BPF_LSH, BPF_REG_6, 32),
	BPF_ALU64_IMM(BPF_RSH, BPF_REG_6, 32),
	BPF_ALU64_REG(BPF_ADD, BPF_REG_8, BPF_REG_6),
	BPF_ST_MEM(BPF_B, BPF_REG_8, 0, 0),
	BPF_MOV32_IMM(BPF_REG_0, 0),
	BPF_EXIT_INSN(),
	},
	.prog_type = BPF_PROG_TYPE_SCHED_CLS,
	.fixup_map_hash_48b = { 4 },
	.result = ACCEPT,
	.flags = F_NEEDS_EFFICIENT_UNALIGNED_ACCESS,
},
{
	"jeq32/jne32: bounds checking",
	.insns = {
	BPF_MOV64_IMM(BPF_REG_6, 563),
	BPF_MOV64_IMM(BPF_REG_2, 0),
	BPF_ALU64_IMM(BPF_NEG, BPF_REG_2, 0),
	BPF_ALU64_IMM(BPF_NEG, BPF_REG_2, 0),
	BPF_ALU32_REG(BPF_OR, BPF_REG_2, BPF_REG_6),
	BPF_JMP32_IMM(BPF_JNE, BPF_REG_2, 8, 5),
	BPF_JMP_IMM(BPF_JSGE, BPF_REG_2, 500, 2),
	BPF_MOV64_IMM(BPF_REG_0, 2),
	BPF_EXIT_INSN(),
	BPF_MOV64_REG(BPF_REG_0, BPF_REG_4),
	BPF_EXIT_INSN(),
	BPF_MOV64_IMM(BPF_REG_0, 1),
	BPF_EXIT_INSN(),
	},
	.prog_type = BPF_PROG_TYPE_SCHED_CLS,
	.result = ACCEPT,
	.retval = 1,
},
