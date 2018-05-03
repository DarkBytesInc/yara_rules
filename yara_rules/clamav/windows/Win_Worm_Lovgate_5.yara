rule Win_Worm_Lovgate_5
{
strings:
	$a0 = { 4b4847b3916ef55c181f4ca9ceef2c6ed7614bdb569955f018bb28fdcc17cef93a28c27e385db08d70653a65aae591cd20dce4b9a73daa8c7955 }

condition:
	$a0
}

        
