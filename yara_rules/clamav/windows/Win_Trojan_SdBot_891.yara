rule Win_Trojan_SdBot_891
{
strings:
	$a0 = { cca5017a50fc47de1526bc480da3206756825253cab43323856711ec1923a4b0e10d4c5533e232a63cc718505270564d53479170a6332626d33951354a25b8dd6cc27330263469a16577207921009557218ce5c98628f4b9c14b4d3c3d821433308473e835c9093147a02c30c5500ab7470dc8ebee14642a2dbde924a4208b59ceb89dee }

condition:
	$a0
}

        