rule Win_Trojan_SdBot_4001
{
strings:
	$a0 = { 0cbdbc93cb9609d920dd4bd657ce6a8410ff935d09f8d2349994f719596a8f3a787f0456c61537ed3cfa6fd84804ac490470143abb59b233522d2bf4fef54dac8872ac5fca3440c1fc37411ee11ba91e4baa8ddaf040ebc1842f49fdaeba341158efff09 }

condition:
	$a0
}

        
