rule Win_Dropper_Microjoin_23
{
strings:
	$a0 = { eb156d505b55f692f70829b224104ab1a2beaeaf33b474dcd2a70ea5591b526861a0f5252124410aa44db2217d424df26cddda36f8a89ade8d5b3bcb3aabe3747786591d0a553b2bb538ae2f0442f9a12d74faa175562c336e30ae2248855dd8bbe7d1cece4effedbffdb13739f77cdef371dfb9f7eef304da3c02b709 }

condition:
	$a0
}

        
