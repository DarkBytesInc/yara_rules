rule Win_Downloader_Dadobra_221
{
strings:
	$a0 = { fe02c376156f8c1393e2cbf6850cc27329e4fce3f19f83e917cbbd290ca1f03f64ffe3f6932466b033a02f1c1bf1a71d87361c395d018ff6582eccacf325948238275538e2abbcd09cfb3cf853741544824e28985f61b3bf8b3b }

condition:
	$a0
}

        
