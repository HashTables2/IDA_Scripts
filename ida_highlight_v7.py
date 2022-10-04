from idautils import *
from idc import *

#Color the Calls and sub functions grey
heads = Heads(get_segm_start(get_screen_ea()), get_segm_end(get_screen_ea()))
funcCalls = []
for current in heads:
	if (print_insn_mnem(current) == "call" or "sub" in print_operand(current, 0)
		or print_operand(current, 0) == "offset StartAddress"):
		funcCalls.append(current)

print("Number of calls and sub functions: %d" % (len(funcCalls)))

for current in funcCalls:
	set_color(current, CIC_ITEM, 0x5b5b5b5b)


#Color Anti-VM instructions red and print their location
heads = Heads(get_segm_start(get_screen_ea()), get_segm_end(get_screen_ea()))
antiVM = []
for current in heads:
	if (print_insn_mnem(current) == "sidt" or print_insn_mnem(current) == "sgdt"
		or print_insn_mnem(current) == "sldt" or print_insn_mnem(current) == "smsw"
		or print_insn_mnem(current) == "str" or print_insn_mnem(current) == "in"
		or print_insn_mnem(current) == "cpuid"):
		antiVM.append(current)

print("Number of potential Anti-VM instructions: %d" % (len(antiVM)))

for current in antiVM:
	print ("Anti-VM potential at %x" % current)
	set_color(current, CIC_ITEM, 0x0000ff)


#Color anti-debugging measures purple and print their location
heads = Heads(get_segm_start(get_screen_ea()), get_segm_end(get_screen_ea()))
antiDbg = []
for current in heads:
	if ((print_insn_mnem(current) == "int" and (print_operand(current, 0) == "3" or print_operand(current, 0) == "2D")) or print_insn_mnem(current) == "rdtsc" or print_insn_mnem(current) == "icebp"):
		antiDbg.append(current)

print("Number of potential Anti-Debugging instructions: %d" % (len(antiDbg)))

for current in antiDbg:
	print("Anti-Debugging potential at %x" % current)
	set_color(current, CIC_ITEM, 0xff00aa)


#Color push/ret combinations yellow as a shellcode
heads = Heads(get_segm_start(get_screen_ea()), get_segm_end(get_screen_ea()))
push_ret = []
previous = 0
for current in heads:
	if (print_insn_mnem(current) == "ret" and print_insn_mnem(previous) == "push"):
		push_ret.append(current)
	previous = current

print("Number of push/ret instructions: %d" % (len(push_ret)))

for current in push_ret:
	set_color(current, CIC_ITEM, 0x00ffff)


#Color non-zeroing out xor instructions green
heads = Heads(get_segm_start(get_screen_ea()), get_segm_end(get_screen_ea()))
xor = []
for current in heads:
	if (print_insn_mnem(current) == "xor"):
		if (print_operand(current,0) != print_operand(current,1)):
			xor.append(current)

print("Number of xor: %d" % (len(xor)))

for current in xor:
	set_color(current, CIC_ITEM, 0x8fdf98)

