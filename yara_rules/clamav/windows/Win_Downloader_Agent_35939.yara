rule Win_Downloader_Agent_35939
{
strings:
	$a0 = { 68e4114000e8f0ffffff000000000000300000003800000000000000ab43a1b1f34a454e950f390cd0d691d5000000000000010000000d0a50726976f1e85642004c7aa70000000007000000e41f4000070000008c1f400007000000481f400006000000301f400007000000e81e400007000000a01e400007000000581e4000 }

condition:
	$a0
}

        