rule Win_Trojan_Mybot_8438
{
strings:
	$a0 = { 86f33d375cbf011ff8609903371b462cdfeeb77e85e083470bc8c18f97d7c227543381befcf32d7b0f65c835812c0f5b75913f489eabb06e856ba50ffb3e3aacb04d195baf4746ffeee475a3aef0ca7d57a504dddc }

condition:
	$a0
}

        
