rule Win_Trojan_Agent_32734
{
strings:
	$a0 = { 05fe76ab33d5193b0d0b40adffa1ff60fdff17fa375e7cefebd121880673453be87ccf5bf1c5ba64e7d1ffffff5b8ee750c9093c8c67f89df0a3ca33f19a0bdbb2a6daafad469871567fe1f61805385f7cf65d334ff2951c6a2272ff37fad2362bce1e07acfc0c2cee6a201bd9c15159ffffffff0b1f3874ae702931122f1432 }

condition:
	$a0
}

        
