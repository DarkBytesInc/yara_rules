rule Win_Trojan_Agent_32808
{
strings:
	$a0 = { ae5da69204df00f6f9e7ebe6c871d4d001f359c4398b77c7d80c62387efa857db8c2643b3fb8061e6672d7e75c5cfdcac666fcf2afcd40f3f5622b0e0409a10c08fcd2ade0ff71fbcd49f8236295227b9905c5ca13f6dc9087d1 }

condition:
	$a0
}

        
