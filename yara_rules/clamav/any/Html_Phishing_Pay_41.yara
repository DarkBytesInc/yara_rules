rule Html_Phishing_Pay_41
{
strings:
	$a0 = { 7365616d7320746f206265206e6f206c6f6e676572207468652073616d65207769746820796f75722063757272656e7420637265646974206361726420696e666f726d6174696f6e20746861742077652068617665206f6e2066696c652e20696620796f75206368616e676564 }

condition:
	$a0
}

        