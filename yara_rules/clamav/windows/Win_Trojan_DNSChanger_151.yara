rule Win_Trojan_DNSChanger_151
{
strings:
	$a0 = { c3cd47c8584ff1cb705196e8f913c605cdca991168d5d1cb70dd554f70ced156edc20dc7e44aba2277ced14f30430d36725b580c75ced11ec31e5be46f44cecbe5bad1e1a8df11ccc0cde783800ed2849a1812cc2853190c70f9991dc02429cbe5caba5f }

condition:
	$a0
}

        
