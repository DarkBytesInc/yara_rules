rule Win_Worm_Plexus_3
{
strings:
	$a0 = { 76f2895dd08d45a450ff1504104000f645d00174110fb745d4eb0e803e2076d84689758cebf56a0a5850565353ff153410400050e8d3fcffff89459850ff15641040008b45ec8b088b09894d885051e80f0000005959c38b65e8ff7588ff156c104000ff2568104000ff255810400068000003006800000100e8130000005959c333c0c3c3ccccccccccccff257c104000ff25781040 }

condition:
	$a0
}

        