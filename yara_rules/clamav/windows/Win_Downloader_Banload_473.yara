rule Win_Downloader_Banload_473
{
strings:
	$a0 = { b463be3f885b8ccce09ef71e0e46ff1cd6614dbe3ede9545d4f35dba206b5c79f86531c5b523ecc252523d92b7bdf284984b07caac62c01b5b09f8da97aaa4c81f51aefb112ecc80cb6c22b120c51460a971add2 }

condition:
	$a0
}

        
