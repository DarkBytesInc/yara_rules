rule Win_Downloader_Small_2789
{
strings:
	$a0 = { 9cd60d058ad6628f02f8f73378d6f921c809eab8b9ee9bd44e4fdd51e5f43b1fe1363407f8fa61c824d6b59de11b134ced98bc64a2d6f23990ce3b5b657e1cf77e5ed4c8ccce2e455683ce1c130ecd23710a28ff8a3df72e3a56a8c310dc1d6035dbe716fb29b7cdc6f34325d760f2226b8c }

condition:
	$a0
}

        
