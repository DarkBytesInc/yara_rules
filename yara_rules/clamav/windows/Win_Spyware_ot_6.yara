rule Win_Spyware_ot_6
{
strings:
	$a0 = { 536561727369076e6720666f8e92ffb4e567771064690a12afe4eea890004e49434b202503730a555345527b110022686f746d61696c3c2e6377f9871c }

condition:
	$a0
}

        