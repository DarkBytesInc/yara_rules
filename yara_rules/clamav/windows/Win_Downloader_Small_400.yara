rule Win_Downloader_Small_400
{
strings:
	$a0 = { 72120000000000009e1200008c12000000000000801100000000000025735c25632563256325632563256325632563256325632e6578650025735c53796d616e7465630050726f6772616d46696c6573000000006162636465666768696a6b6c6d6e6f7072737475767778797a30313233343536373839006874 }

condition:
	$a0
}

        