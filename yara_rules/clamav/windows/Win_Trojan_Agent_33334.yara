rule Win_Trojan_Agent_33334
{
strings:
	$a0 = { 23b12015113ba7c6afb0b3028947cb0ff2066afdbb69dc52df16763098c267bcc22e3bea74c06670a9bc909ed6c1fef1585d2f22bc587f6082639d6e437db69620cd09364385b1e396e3a6cb5ef1 }

condition:
	$a0
}

        
