rule Win_Trojan_Agent_33611
{
strings:
	$a0 = { 220d1f0794e7aa18c732bb0b08f8dc664314e58740945b9bfa52e6cbe859cf3bc55f186513f3ccdab1f607eb81f62bc1a58ccd46e5faa5ca3b0732652e8c5f0af9a0315d8e12810179d82b0c8f0ce8c3901b }

condition:
	$a0
}

        
