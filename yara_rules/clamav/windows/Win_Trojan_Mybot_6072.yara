rule Win_Trojan_Mybot_6072
{
strings:
	$a0 = { af7d384fd4261e0dcfd20403075c3988ebd071e539cd2498b2589d483a78cb0c871cbfc8a41ba7533ef19f26b3e29dbd7162b247f7ae707dc3119da3ee3a208b5e1d129a758c11175834bb52a2ba08edcd1f9568f4f81ebea1 }

condition:
	$a0
}

        
