rule Win_Spyware_Banker_2342
{
strings:
	$a0 = { c85c73dfac45d6c0a71035f844df06b108c5c0ca05b57a8eff0be9517204e3190a854bb3bddd8fd44f42c610167ce04a67ed356180dac8443e82acd6d25fd4e7a47a90bedaecd15b4b948318a3b275e9700606fd806385f3820130c12bbae73603045591d7b9a4fdad021e95bd3a }

condition:
	$a0
}

        