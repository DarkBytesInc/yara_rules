rule Win_Downloader_Zlob_1384
{
strings:
	$a0 = { 30001020000000e835000000c70424043000106800300010a328300010e8bcffffff5959c38b0d3030001085c97411a1283000108d0c885150e8a0ffffff5959c3ff7424046a08ff154420001050ff1550200010c38b4c2408668339008b442404578bf8744733d2668b106685d25374392bc16685d28b4c2410741c668b116685d2742b0fb71c080fb7d22bda7509414166833c0800 }

condition:
	$a0
}

        