rule Win_Spyware_Banker_2688
{
strings:
	$a0 = { 0cbae37df755780790074c607d540048d9e4aa23137b840f15cb925360a42298ae021875f13dc755b63820fc03702dc7dbdde4135db1a88addcfaf14cfd9637c8aac036058ac62713106ba68efd1 }

condition:
	$a0
}

        
