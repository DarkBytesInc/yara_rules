rule Win_Dropper_Agent_33441
{
strings:
	$a0 = { 088aa917672a2df028a7e9ef3225f22f2dd05d0bd0cae479a3c1e49e8de77a85d2482573442d1872ce4f55b752fc6f5d56080b8a3838293edd95cecbe55a31451ca650c2adeee7cee252dea1055e451b40bbc15bfaacde009198bbac5c5cd389f1574afc91b8 }

condition:
	$a0
}

        
