rule Win_Trojan_VGEN_291
{
strings:
	$a0 = { b8e203bae6000500003b060200722ab409ba1c01cd21b8014ccd214e6f7420656e6f756768206d656d6f7279242020 }

condition:
	$a0
}

        
