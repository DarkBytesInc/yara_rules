rule Win_Trojan_Spambot_222
{
strings:
	$a0 = { 7bcbe7cedbf5e6cef1db0dfcfa286e7e4a12faffffff24c0b0c7b0b1af332f0c55453c509ce50e533650f4ef3a0a23715703bfffffff3fdd01124ef54289b688514c2ebb54a651a88ad4534f968b9182cb426064ffffffff62a9f0a07c231561da93bdea7883c4154c8b84c88e50 }

condition:
	$a0
}

        
