rule Win_Trojan_Antitrace_3
{
strings:
	$a0 = { b82135cd218c063901891e3701ba1b01b425cd21ba3b01cd27ebfe66501e33c08ed80eb81901506658668706040066870604001f6658ea }

condition:
	$a0
}

        
