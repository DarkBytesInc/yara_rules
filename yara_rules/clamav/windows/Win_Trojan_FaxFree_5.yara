rule Win_Trojan_FaxFree_5
{
strings:
	$a0 = { 064c028cc00510002e010635022e01063102501e06b8524dcd213d4443745433c98ec18cd8488ed850b05a3806 }

condition:
	$a0
}

        
