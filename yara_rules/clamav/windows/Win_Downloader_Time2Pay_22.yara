rule Win_Downloader_Time2Pay_22
{
strings:
	$a0 = { 66c22eff927f81654720b0756215a069712cbe65622084b0faba2d8b7761da578ebb51c9fa761233d5b77cf7d40ca6157b41e0a516322d7f6f07c03bd437395f5986878befc43ec0000b848d40f60eb6fa8d8533de155b5dff83dbc3068c1dca68d31965ce8e1e95c8cf1ccfd0a96866bc4202bdd497c9d306916f }

condition:
	$a0
}

        