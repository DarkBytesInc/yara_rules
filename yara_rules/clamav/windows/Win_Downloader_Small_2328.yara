rule Win_Downloader_Small_2328
{
strings:
	$a0 = { c855b48389e581ec9400000081ecfc0c000089e380e1f28925da194000a14a60400080ea6389831d020000a14660400080ea2c898359020000c783700b000000000000c7836108000000000000c783830700 }

condition:
	$a0
}

        