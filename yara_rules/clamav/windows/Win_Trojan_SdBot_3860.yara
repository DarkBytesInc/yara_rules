rule Win_Trojan_SdBot_3860
{
strings:
	$a0 = { 1e1330e51d17acf55fe94efcd069206df7e0bcfd11dab5832709fd509169d19c7029be76f0e0c89966fcbd6ebaef0ab029de6cdd6fd34c7e2f2e89d6d5e89d100246829ae958ca5e479941b9b00967291d17b337da }

condition:
	$a0
}

        
