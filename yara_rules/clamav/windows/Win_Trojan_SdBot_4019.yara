rule Win_Trojan_SdBot_4019
{
strings:
	$a0 = { 0d2b292bd446c8e986153ac914c50eb27cfec57bf9fe73d7f07194db4c57fdb46bb8bf77f48e3a2a66829ccdf6cd4fbcdbad9c00c0da0fb299da8050d35a337f05040b856b9f9c3462a7088f339702a3fbd942866969 }

condition:
	$a0
}

        
