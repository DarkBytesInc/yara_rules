rule Win_Trojan_VGEN_428
{
strings:
	$a0 = { 9a000048005589e531c09a7c024800bffe021e57bf46020e5731c0509ab40648009a09064800b04350e8eafeb002b9ff }

condition:
	$a0
}

        
