rule Win_Spyware_Banker_256
{
strings:
	$a0 = { 296bf22adc1c9eafd1d3e4a9a42e204af2abfe43539f637eb60a409c176790ed76c99d7e489ae3b7ed760ca6e1998d5de72ff501fda025e78d934ac0b977665f4c136bbce3bbe382a9bbe0f2e1d1502acacd1bb53e82c4ae7425a2aed0c90d3579e9cefaac1efb23058f7fc4c895ecff425cdcabb60329717bbcefedbb6dfbd5 }

condition:
	$a0
}

        
