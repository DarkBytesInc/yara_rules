rule Win_Trojan_SdBot_3849
{
strings:
	$a0 = { b5e854d2efc9fc4a771253dc524cb7991ff5a51cfbacd23629c8b827b05537194cbec66cfe800e6ea964627004998533f7134d3aee73c576fef9ae8ebcb4806eca180dda4169a71d92822b5a0d651e0fd0075a9513 }

condition:
	$a0
}

        
