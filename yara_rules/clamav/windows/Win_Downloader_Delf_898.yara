rule Win_Downloader_Delf_898
{
strings:
	$a0 = { a04ebae2c59ee2fdfc6ef5639f0b6bd7277033c3e02880c1b88c7b0aed99efc196f6cb4d7d985dc42a57024f9aa0c05a85a41db29ce1d380d9fec5fbde1f10ee21014de3aef0443d5de35f1a588e11bc1df106251a118872bfb7200bd3e4e23942db84c4 }

condition:
	$a0
}

        
