rule Win_Trojan_Pakes_936
{
strings:
	$a0 = { 202ca158cbf16edce15daff27115fbac8186f5055d5caf97fd253b0c8571b65afd43d66e85eace799dcccc5e9fcd1d4ef99fba51c3a9d6884d9e579e8e3c36e7742aa9e18c11f94f807b5d5b86296c7888b5397fe25201571786d3665cea356bd18226a2b2b47d2dc132f0ec66cd501a3d57ae7e800ac611e859a7 }

condition:
	$a0
}

        