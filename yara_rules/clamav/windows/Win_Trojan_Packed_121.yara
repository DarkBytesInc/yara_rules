rule Win_Trojan_Packed_121
{
strings:
	$a0 = { 608bcce824ffffff61c36a009c608bcce803000000619dc3558bec51568bf1c745fc20020000e800000000582d130400000345fc837e240075058b4014eb038b4018894624c745fc58060000e800000000582d390400000345fc8b000146245ec9c36a }

condition:
	$a0
}

        