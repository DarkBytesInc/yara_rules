rule Win_Trojan_SdBot_830
{
strings:
	$a0 = { 2e3132c54b6886283f764d7572e66d3d2d42b8795220c430333e77166974631fae8137347032 }

condition:
	$a0
}

        
