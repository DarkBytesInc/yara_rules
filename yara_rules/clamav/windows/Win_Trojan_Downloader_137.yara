rule Win_Trojan_Downloader_137
{
strings:
	$a0 = { 282225753030306225753030306225753030306225753030306222293b(22|27)293b646f63756d656e742e777269746528(22|27)766172696d616765733d22616374697665782e222b6576696c2b2272746c616c6c6f636174656865617072746c63726561746568656170223b }

condition:
	$a0
}

        