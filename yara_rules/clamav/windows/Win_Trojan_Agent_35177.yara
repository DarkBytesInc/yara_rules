rule Win_Trojan_Agent_35177
{
strings:
	$a0 = { 9c8bd487f6e8000000005b4f57584e85c38bcb81eb97100100f7d266baa845533ce781c136000000406800000000 }

condition:
	$a0
}

        
