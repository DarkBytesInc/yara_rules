rule Win_Downloader_Small_2825
{
strings:
	$a0 = { 50ea54fc4b354214a72d73977ff04238ec00768422dcff53562820e32611aabaced85c74ef0819d68a56fe33a7302dfeed3916ebbd1a1afeb88dce268bb01a07e0a1fd16878ab56a9320212ce80ac1ecd958b88aaf7a1e4292574da6a8424e365ae1a4ca5b93a5c8c6febda2d4e732cc3aa6 }

condition:
	$a0
}

        
