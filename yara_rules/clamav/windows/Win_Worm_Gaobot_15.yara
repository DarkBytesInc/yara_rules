rule Win_Worm_Gaobot_15
{
strings:
	$a0 = { 225435852874d4410080cc5c7e000080fb7c21a9f490430080c62258a8c64218ffff7fa8f456410080c64218ffff7fab287447420080c62256a8c64298ffff7f28743f420080c64298ffff7f2b28f438 }

condition:
	$a0
}

        