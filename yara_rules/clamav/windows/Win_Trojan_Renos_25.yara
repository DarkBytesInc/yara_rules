rule Win_Trojan_Renos_25
{
strings:
	$a0 = { 0195f4fdffff3195b0feffff85d274208b855cffffff01d01385d4fdffff83fa00730d420b9504ffffff1395e4fdffffb99e0f0000238d58feffff81e986000000318d9cfeffffff857cffffff018d94feffffff8ddcfdffff4981e9001a000083f90074 }

condition:
	$a0
}

        
