rule Win_Worm_SQL_2
{
strings:
	$a0 = { 61696c5b72616e646f6d28302c20656d61696c2e6c656e677468202d2031295d202b2022202d7375626a6563742022202b20575363726970742e417267756d656e74732830292c20302c2074727565293b0d0a0d0a64657374726f7928636c6566696c65293b0d0a64657374726f792870617468202b202273656e64 }

condition:
	$a0
}

        