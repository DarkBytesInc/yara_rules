rule Win_Downloader_Banload_139
{
strings:
	$a0 = { e282893a68495cb41e1112455ea16b2bd6f23c9fc4fac57aa6e0d31783352aa1403f63032f97ac4facf361329b59f53ec20c19541ba1aa2281ee68646269a282d8f5aab5ac95173df39b0f26fac9f3a228efaab1b94f4938fc1655d6b81b40d94fcedf8e6df05c369482c37c6ab20d5eb46907685c5cb7d90cc06400b854387b633d7ba72ae97c80b697a46026ce58b474f14aed06ab }

condition:
	$a0
}

        