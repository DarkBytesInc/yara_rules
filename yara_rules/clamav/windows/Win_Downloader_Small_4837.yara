rule Win_Downloader_Small_4837
{
strings:
	$a0 = { 8cd237b6db47ee4e2eff5cb9981c2fdc46f3bb6b74c758a64c4bd5a668624ac7f1143893c89a26525fdda9e40fc7c8293a35f2969c0cd32372d405abe9d87a8c6f25e46454a4d3b9bc1413e7f91ada21c30e70b5edebf6afc90741f5bc7a79b3f0bd59a0557c0ab2df0f68d0ac6b0dae8f3928bc89c878baa679ed }

condition:
	$a0
}

        
