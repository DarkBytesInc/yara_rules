rule Win_Downloader_Small_2630
{
strings:
	$a0 = { 2e6578650033c064034030780c8b400c8b701cad8b4008eb098b40348d407c8b403c95bf8e4e0eece884ffffff83ec04832c243cffd09550bf361a2f70e86fffffff8b5424fc8d52ba33db535352eb2453ffd05dbf98fe8a0ee853ffffff83ec04832c2462ffd0bf7ed8e273e840ff }

condition:
	$a0
}

        
